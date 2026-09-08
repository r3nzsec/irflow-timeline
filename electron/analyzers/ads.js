const { dbg } = require("../logger");
const { parseTimestampMs } = require("../utils/parse-timestamp");

/**
 * Synthesize an ADS incident verdict from the assembled result. PURE (no DB/clock) so it is
 * unit-testable and deterministic.
 *
 * DESIGN — keep impact and evidentiary strength separate, and never overclaim:
 *   • `severity` reflects IMPACT (executable hidden in a stream > a benign named stream; MOTW strip;
 *     ingress of MOTW-marked executables).
 *   • `confidence` is gated on forgery-resistant corroboration: 'corroborated' only when USN named-stream
 *     writes / Sysmon EID 15 back the flagged stream(s) (or USN backs a MOTW strip); 'weak' when
 *     companions are loaded but don't corroborate; 'observed' for single-source $MFT. NOTE: a stream's
 *     EXISTENCE is structural ($MFT), so $SI timestomping degrades the TIMING (a factor), not confidence
 *     in the finding itself.
 *   • MITRE entries are candidate techniques tagged with their own confidence, not assertions.
 *   • `coverage` states what this assessment can and cannot see (raw-$MFT content limits, companion
 *     availability, $SI reliability) so an empty lane isn't read as an all-clear.
 */
function _buildAdsVerdict(o) {
  const totalWithZoneId = o.totalWithZoneId || 0;
  const totalStreamCarriers = o.totalStreamCarriers || 0;
  // Score/headline on the BENIGN-EXCLUDED carrier count so known OS/app streams (WofCompressedData,
  // SmartScreen, …) never inflate severity or read as a finding; keep the raw count for display only.
  const nonBenign = o.nonBenignStreamCarriers != null ? o.nonBenignStreamCarriers : totalStreamCarriers;
  const benignExcluded = Math.max(0, totalStreamCarriers - nonBenign);
  const execStreams = o.totalAdsExecStreams || 0;
  const execDownloads = o.execCount || 0;
  const motwLoss = (o.motwSuspicious || []).length;
  const internalHostCount = (o.internalHosts || []).length;
  const zb = o.zoneBreakdown || {};
  const corr = o.correlation || {};
  const sr = o.siReliability || {};
  const internetDl = zb.internet || 0;
  const usnCorr = (corr.carriersUsnCorroborated || 0) > 0;
  const evtxCorr = (corr.carriersEvtxCorroborated || 0) > 0;
  const anyCarrierCorroborated = usnCorr || evtxCorr;
  const motwCorr = (corr.motwCorroborated || 0) > 0;
  const siSuspect = sr.suspectStreamCarriers || 0;

  // Coverage block — what this assessment can and cannot see.
  const coverage = [];
  if (o.hasAdsStreams) coverage.push({ label: "Raw $MFT stream enumeration", detail: "Non-Zone alternate-stream names + sizes are recovered; resident PE/MZ content is flagged. Non-resident stream CONTENT is not in $MFT — extract with MFTECmd / fls to hash it.", status: "partial" });
  else if (o.isAdsCol) coverage.push({ label: "MFTECmd per-stream rows", detail: "Per-stream IsAds entries (stream names) are available from the MFTECmd CSV; non-resident stream CONTENT is not — extract with MFTECmd / fls to hash it.", status: "partial" });
  else coverage.push({ label: "Stream visibility", detail: "Only HasAds / Zone.Identifier are present; non-Zone stream names are not enumerable on this tab.", status: "gap" });
  coverage.push(corr.usnAvailable
    ? { label: "USN ($J) corroboration", detail: `${(corr.usnNamedStreamTotal || 0).toLocaleString()} named-stream/StreamChange op(s); ${corr.carriersUsnCorroborated || 0} carrier(s) corroborated.`, status: usnCorr ? "ok" : "partial" }
    : { label: "USN ($J) corroboration", detail: "No USN journal companion loaded — stream writes can't be confirmed against forgery-resistant evidence.", status: "gap" });
  coverage.push(corr.evtxAvailable
    ? { label: "EVTX (Sysmon EID 15)", detail: `${(corr.evtxStreamCreateTotal || 0).toLocaleString()} FileCreateStreamHash event(s); ${corr.carriersEvtxCorroborated || 0} carrier(s) corroborated.`, status: evtxCorr ? "ok" : "partial" }
    : { label: "EVTX (Sysmon EID 15)", detail: "No EVTX companion loaded — the stream-creating process + hash are unavailable.", status: "gap" });
  if (sr.available) {
    if ((sr.totalStreamCarriers || 0) === 0) coverage.push({ label: "$SI reliability", detail: "No non-Zone stream carriers to assess for $SI timestomping.", status: "partial" });
    else coverage.push({ label: "$SI reliability", detail: siSuspect > 0 ? `${siSuspect.toLocaleString()} of ${(sr.totalStreamCarriers || 0).toLocaleString()} carrier(s) have timestomped-looking $SI — stream TIMING is unreliable (existence is structural).` : "No timestomped-looking $SI among stream carriers.", status: siSuspect > 0 ? "partial" : "ok" });
  }

  if (totalWithZoneId === 0 && totalStreamCarriers === 0) {
    return {
      severity: "info", severityScore: 0, confidence: "none",
      headline: "No alternate-data-stream or download-provenance findings.",
      narrative: "No files carry a non-Zone named stream and no Zone.Identifier (Mark-of-the-Web) download markers were found in the analyzed $MFT. Absence here does not rule out streams stripped before acquisition, or payloads stored only in non-resident streams; corroborate with the USN journal (StreamChange) and Sysmon EID 15.",
      factors: [], mitre: [], coverage,
    };
  }

  const factors = []; const mitre = []; let score = 0;

  // Executable/script hidden in a non-Zone stream — the namesake T1564.004 tradecraft. The non-exec
  // residual (nonBenign carriers beyond the exec ones) adds a small, capped blast-radius term so a
  // large carrier population isn't scored identically to a tiny one; the exec cap stays dominant.
  if (execStreams > 0) {
    score += Math.min(48, 28 + execStreams * 7);
    factors.push({ label: "Executable/script hidden in a stream", detail: `${execStreams.toLocaleString()} non-Zone carrier(s) with an exec/script stream (resident PE/MZ content, or an executable stream-name extension)`, severity: "high" });
    mitre.push({ technique: "T1564.004", name: "Hide Artifacts: NTFS File Attributes (ADS)", confidence: anyCarrierCorroborated ? "corroborated" : "observed", evidence: evtxCorr ? "Sysmon EID 15 stream-create events on carrier files" : usnCorr ? "USN named-stream writes on carrier files" : "non-Zone named $DATA streams with executable content/extension ($MFT)" });
    if (evtxCorr) score += 8; // creation confirmed, with actor + hash
    if (usnCorr) score += 4;  // forgery-resistant named-stream write confirmed
    if (nonBenign > execStreams) score += Math.min(8, Math.round((nonBenign - execStreams) / 3));
  } else if (nonBenign > 0) {
    score += Math.min(18, 6 + nonBenign);
    factors.push({ label: "Non-Zone named streams", detail: `${nonBenign.toLocaleString()} file(s) carry a named alternate data stream that is not Zone.Identifier${benignExcluded > 0 ? ` (${benignExcluded.toLocaleString()} known-benign OS/app stream(s) excluded)` : ""}`, severity: "medium" });
    mitre.push({ technique: "T1564.004", name: "Hide Artifacts: NTFS File Attributes (ADS)", confidence: anyCarrierCorroborated ? "corroborated" : "observed", evidence: "non-Zone named $DATA streams ($MFT)" });
  }

  // MOTW loss / strip on extracted executables.
  if (motwLoss > 0) {
    score += Math.min(22, 8 + motwLoss * 3);
    factors.push({ label: "MOTW loss on extracted executables", detail: `${motwLoss.toLocaleString()} executable/script(s) extracted from a Zone-marked archive carry NO Zone.Identifier${motwCorr ? ` (${corr.motwCorroborated} USN-corroborated as a real stream removal)` : ""}`, severity: "high" });
    mitre.push({ technique: "T1553.005", name: "Subvert Trust Controls: Mark-of-the-Web Bypass", confidence: motwCorr ? "corroborated" : "observed", evidence: motwCorr ? "USN NamedDataTruncation/StreamChange on the extracted file" : "archive carried Zone.Identifier; extracted executable did not (inference)" });
  }

  // Ingress: MOTW-marked executable downloads.
  if (execDownloads > 0) {
    score += Math.min(15, execDownloads);
    factors.push({ label: "Downloaded executables (MOTW)", detail: `${execDownloads.toLocaleString()} executable/script download(s) carry a Zone.Identifier`, severity: execDownloads >= 5 ? "high" : "medium" });
    mitre.push({ technique: "T1105", name: "Ingress Tool Transfer", confidence: "observed", evidence: "executable/script files carrying a Zone.Identifier (download provenance)" });
  }
  if (internetDl > 0) score += Math.min(8, internetDl / 50);
  if (internalHostCount > 0) { score += 5; factors.push({ label: "Internal-source downloads", detail: `download provenance from ${internalHostCount} internal/private host(s) — possible lateral staging`, severity: "medium" }); }

  if (anyCarrierCorroborated) factors.push({ label: "Cross-artifact corroboration", detail: `${corr.carriersUsnCorroborated || 0} carrier(s) match USN named-stream writes; ${corr.carriersEvtxCorroborated || 0} match Sysmon EID 15`, severity: "info" });
  if (siSuspect > 0) factors.push({ label: "$SI timing unreliable", detail: `${siSuspect.toLocaleString()} carrier(s) have timestomped-looking $SI — the WHEN is unreliable; the stream's existence is structural`, severity: "medium" });

  score = Math.min(100, Math.round(score));
  const severity = score >= 70 ? "critical" : score >= 45 ? "high" : score >= 25 ? "medium" : score >= 10 ? "low" : "info";

  // Confidence — gate on the corroboration of THE HEADLINE finding specifically, never on a different
  // (separately-corroborated) lane. The headline lead is, in priority order: exec stream > named stream
  // > download. A corroborated MOTW strip must NOT launder an uncorroborated stream headline as
  // "corroborated" (and vice-versa). $SI-suspect degrades TIMING (a factor), not the existence finding.
  const headlineIsStream = execStreams > 0 || nonBenign > 0;
  const companionLoaded = corr.usnAvailable || corr.evtxAvailable;
  let confidence, confNote;
  if (headlineIsStream) {
    if (anyCarrierCorroborated) { confidence = "corroborated"; confNote = "the flagged stream(s) are backed by forgery-resistant USN/EVTX evidence"; }
    else if (companionLoaded) { confidence = "weak"; confNote = "companion USN/EVTX tabs are loaded but do not corroborate the flagged stream(s)"; }
    else { confidence = "observed"; confNote = "single-source $MFT — load a USN ($J) or EVTX (Sysmon) companion tab to corroborate stream activity"; }
  } else if (motwLoss > 0) {
    if (motwCorr) { confidence = "corroborated"; confNote = "the Mark-of-the-Web strip is corroborated by forgery-resistant USN evidence"; }
    else if (corr.usnAvailable) { confidence = "weak"; confNote = "a USN companion is loaded but does not corroborate the suspected MOTW strip"; }
    else { confidence = "observed"; confNote = "MOTW-loss is inferred from $MFT (archive had a Zone marker, extracted file did not) — load a USN ($J) companion to corroborate the strip"; }
  } else { confidence = "observed"; confNote = "based on Zone.Identifier download markers in $MFT"; }

  const cap = severity.toUpperCase();
  // Lead must describe the finding that actually drives the confidence label (so a corroborated MOTW
  // strip never sits behind an uncorroborated download lead, and vice-versa).
  let lead;
  if (execStreams > 0) lead = `${execStreams.toLocaleString()} file(s) hide an executable/script in a non-Zone stream`;
  else if (nonBenign > 0) lead = `${nonBenign.toLocaleString()} file(s) carry a non-Zone named stream`;
  else if (motwLoss > 0) lead = `${motwLoss.toLocaleString()} executable(s) lost their Mark-of-the-Web on extraction`;
  else if (execDownloads > 0) lead = `${execDownloads.toLocaleString()} executable download(s) carry Mark-of-the-Web`;
  else lead = `${totalWithZoneId.toLocaleString()} Mark-of-the-Web download marker(s)`;
  const headline = `${cap} (${confidence}): ${lead}.`;

  const bits = [];
  bits.push(`${nonBenign.toLocaleString()} non-Zone stream carrier(s) of forensic interest${execStreams > 0 ? `, ${execStreams.toLocaleString()} carrying executable/script content` : ""}${benignExcluded > 0 ? ` (${benignExcluded.toLocaleString()} known-benign OS/app stream(s) excluded)` : ""}${totalWithZoneId > 0 ? `; ${totalWithZoneId.toLocaleString()} Mark-of-the-Web download marker(s)` : ""}.`);
  if (execStreams > 0) bits.push(`The namesake ADS tradecraft (T1564.004) is present: carrier(s) hold a stream whose content is a PE/MZ or whose name has an executable extension.`);
  if (motwLoss > 0) bits.push(`${motwLoss.toLocaleString()} executable(s) extracted from a Zone-marked archive lost their Mark-of-the-Web${motwCorr ? `, ${corr.motwCorroborated} USN-corroborated as a real stream removal` : ""} (T1553.005).`);
  if (anyCarrierCorroborated) bits.push(`Forgery-resistant corroboration: ${corr.carriersUsnCorroborated || 0} carrier(s) match USN named-stream writes and ${corr.carriersEvtxCorroborated || 0} match Sysmon EID 15 (FileCreateStreamHash).`);
  if (siSuspect > 0) bits.push(`${siSuspect.toLocaleString()} carrier(s) carry timestomped-looking $SI — their stream TIMING is unreliable, though the stream's existence is structural ($MFT), not $SI-derived.`);
  bits.push(`Confidence is ${confidence} — ${confNote}. On a raw $MFT, non-resident stream content is not present (only names + sizes); extract and hash flagged streams with MFTECmd before relying on them.`);

  return { severity, severityScore: score, confidence, headline, narrative: bits.join(" "), factors, mitre, coverage };
}

function analyzeADS(meta, opts = {}) {
    // opts.usnMeta / opts.evtxMeta are companion tabs (USN $J / EVTX) reserved for cross-artifact
    // corroboration of MOTW/ADS events; plumbed through now, consumed in a later tier.
    const empty = {
      totalWithAds: 0,
      totalAdsEntries: 0,
      totalWithZoneId: 0,
      downloadedExecutables: [],
      zoneIdFiles: [],
      adsEntries: [],
      topDownloadDirs: [],
      zoneBreakdown: { local: 0, intranet: 0, trusted: 0, internet: 0, restricted: 0, unknown: 0 },
      zoneNoUrlCount: 0,
      referrerUrls: [],
      hostUrls: [],
      prioritizedDownloads: [],
      archiveLineage: [],
      motwSuspicious: [],
      internalHosts: [],
      sourceClusters: [],
      adsAnomalies: [],
      streamCarriers: [],
      totalStreamCarriers: 0,
      totalAdsExecStreams: 0,
      // T6: forgery-resistant cross-artifact corroboration + $SI-reliability landscape.
      correlation: { usnAvailable: false, evtxAvailable: false, usnNamedStreamTotal: 0, evtxStreamCreateTotal: 0, evtxScanned: 0, evtxCapped: false, carriersChecked: 0, carriersUsnCorroborated: 0, carriersEvtxCorroborated: 0, motwCorroborated: 0 },
      siReliability: { available: false, suspectStreamCarriers: 0, totalStreamCarriers: 0, note: "" },
      verdict: null,
      summary: null,
    };
    if (!meta) return empty;

    const db = meta.db;
    // Only accept internally-generated safe identifiers (e.g. "c3") before they are
    // ever interpolated into SQL strings below — closes off SQL injection if colMap
    // is ever populated from an untrusted source.
    const col = (name) => {
      const v = meta.colMap[name];
      return v && /^c\d+$/.test(v) ? v : undefined;
    };
    const hasAds = col("HasAds"), isAds = col("IsAds"), zoneId = col("ZoneIdContents");
    const fn = col("FileName"), ext = col("Extension"), pp = col("ParentPath");
    const entry = col("EntryNumber"), created = col("Created0x10"), fs = col("FileSize");
    const isDir = col("IsDirectory");
    const adsStreamsCol = col("AdsStreams"); // raw-$MFT non-Zone stream descriptors "[!]name(size)|..." (T5)
    // T6: $SI is user-settable, so the stream/download timing on raw $MFT is forgeable. These columns
    // (when present — raw $MFT / MFTECmd) let us flag rows whose $SI looks timestomped, and the
    // companion tabs let us corroborate against forgery-resistant evidence.
    const siFn = col("SI<FN"), uSec = col("uSecZeros");
    const usnMeta = opts.usnMeta || null;
    const evtxMeta = opts.evtxMeta || null;
    if (!hasAds && !isAds && !zoneId) return { ...empty, error: "No ADS columns found (HasAds, IsAds, ZoneIdContents)." };

    const notDir = isDir ? "AND (" + isDir + " IS NULL OR " + isDir + " = '' OR " + isDir + " = 'False')" : "";

    // Helper to parse Zone.Identifier content
    const parseZoneId = (content) => {
      if (!content) return { zone: null, zoneName: "", referrerUrl: "", hostUrl: "" };
      const zoneMatch = content.match(/ZoneId\s*=\s*(\d)/);
      const zone = zoneMatch ? parseInt(zoneMatch[1]) : null;
      const zoneNames = { 0: "Local", 1: "Intranet", 2: "Trusted", 3: "Internet", 4: "Restricted" };
      const referrerMatch = content.match(/ReferrerUrl\s*=\s*(.+?)(?:\r?\n|$)/);
      const hostMatch = content.match(/HostUrl\s*=\s*(.+?)(?:\r?\n|$)/);
      return {
        zone,
        zoneName: zoneNames[zone] || (zone !== null ? `Zone ${zone}` : ""),
        referrerUrl: referrerMatch ? referrerMatch[1].trim() : "",
        hostUrl: hostMatch ? hostMatch[1].trim() : "",
      };
    };
    // Use canonical UTC-aware parser so naive timestamps don't shift on
    // non-UTC analyst hosts (forensic timestamps are conventionally UTC).
    const parseTs = parseTimestampMs;
    const RISKY_EXTS = new Set([".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".jar",".py",".lnk",".iso",".img"]);
    const EXEC_EXTS = new Set([".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".jar",".py"]);
    const ARCHIVE_EXTS = new Set([".zip",".rar",".7z",".iso",".img",".cab",".tar",".gz",".bz2",".xz"]);
    const OFFICE_EXTS = new Set([".doc",".docm",".docx",".xls",".xlsm",".xlsx",".ppt",".pptm",".pptx",".rtf",".one"]);
    // Known-benign OS/app alternate-stream names (lowercased) — surfaced but not flagged suspicious.
    const BENIGN_STREAMS = new Set(["afp_resource", "afp_afpinfo", "com.apple.quarantine", "com.dropbox.attrs", "oecustomproperty", "smartscreen", "wofcompresseddata", "encryptable", "favicon", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}"]);
    const STREAM_NAME_PAT = /:([^:\\]+)$/i;
    const hostFromUrl = (raw) => {
      if (!raw) return "";
      const s = String(raw).trim();
      try {
        const u = new URL(s);
        return (u.hostname || "").toLowerCase();
      } catch {
        const m = s.match(/^\\\\([^\\\/]+)[\\\/]/) || s.match(/^file:\/\/\/{0,2}([^\/\\]+)/i);
        return m ? String(m[1]).toLowerCase() : "";
      }
    };
    const isInternalHost = (host) => {
      if (!host) return false;
      if (/^(localhost|127\.|::1$)/i.test(host)) return true;
      if (/^(10\.)/.test(host)) return true;
      if (/^192\.168\./.test(host)) return true;
      if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return true;
      return !host.includes(".");
    };
    const inferTransferSource = (referrerUrl, hostUrl) => {
      const ref = String(referrerUrl || "").toLowerCase();
      const host = String(hostUrl || "").toLowerCase();
      const combined = `${ref} ${host}`;
      if (/^file:|^\\\\/.test(host) || /^file:|^\\\\/.test(ref)) return "smb/webdav";
      if (/https?:/.test(combined)) return isInternalHost(hostFromUrl(host || ref)) ? "internal web/file portal" : "browser/web";
      if (/ftp:/.test(combined)) return "ftp";
      if (/bits/.test(combined)) return "bits";
      if (/powershell|pwsh/.test(combined)) return "powershell";
      return host || ref ? "network transfer" : "";
    };
    const leafName = (s) => {
      const raw = String(s || "");
      const seg = raw.split(/[\\\/]/).pop() || raw;
      return seg.replace(/:[^:]+$/,"");
    };
    const parentDirRisk = (p) => /\\users\\[^\\]+\\(downloads|desktop|appdata|temp)\\|\\windows\\temp\\|\\users\\public\\/i.test(String(p || "").toLowerCase());

    try {
      // Q1: Summary counts
      const totalWithAds = hasAds ? (db.prepare("SELECT COUNT(*) as cnt FROM data WHERE " + hasAds + " = 'True' " + notDir).get()?.cnt || 0) : 0;
      const totalAdsEntries = isAds ? (db.prepare("SELECT COUNT(*) as cnt FROM data WHERE " + isAds + " = 'True'").get()?.cnt || 0) : 0;
      const totalWithZoneId = zoneId ? (db.prepare("SELECT COUNT(*) as cnt FROM data WHERE " + zoneId + " IS NOT NULL AND " + zoneId + " != ''").get()?.cnt || 0) : 0;

      if (totalWithAds === 0 && totalAdsEntries === 0 && totalWithZoneId === 0) return { ...empty };

      // Zone distribution + source-URL coverage over the FULL Zone.Identifier population (not the
      // most-recent 2000-row detail sample), so the distribution agrees with the headline count.
      // Zone digit read via instr/substr on the first 'ZoneId=' (mirrors parseZoneId for standard
      // '[ZoneTransfer]' blobs); a row with no parseable digit lands in `unknown`, so the six buckets
      // partition the population exactly. `zoneNoUrlCount` = ZoneId present but no HostUrl/ReferrerUrl
      // recorded (URL-less MOTW, or a blob dropped at the parser's size cap) — a coverage signal.
      let zoneBreakdown = { local: 0, intranet: 0, trusted: 0, internet: 0, restricted: 0, unknown: 0 };
      let zoneNoUrlCount = 0;
      if (zoneId && totalWithZoneId > 0) {
        const zc = zoneId;
        const zr = db.prepare(
          "WITH z AS (" +
          " SELECT CASE WHEN instr(" + zc + ", 'ZoneId=') > 0 THEN substr(" + zc + ", instr(" + zc + ", 'ZoneId=') + 7, 1) ELSE '' END AS d," +
          "        (instr(" + zc + ", 'HostUrl=') = 0 AND instr(" + zc + ", 'ReferrerUrl=') = 0) AS nourl" +
          " FROM data WHERE " + zc + " IS NOT NULL AND " + zc + " != ''" +
          " )" +
          " SELECT SUM(d='0') as local, SUM(d='1') as intranet, SUM(d='2') as trusted, SUM(d='3') as internet," +
          "        SUM(d='4') as restricted, SUM(d NOT IN ('0','1','2','3','4')) as unknown, SUM(nourl) as noUrl FROM z"
        ).get() || {};
        zoneBreakdown = { local: zr.local || 0, intranet: zr.intranet || 0, trusted: zr.trusted || 0, internet: zr.internet || 0, restricted: zr.restricted || 0, unknown: zr.unknown || 0 };
        zoneNoUrlCount = zr.noUrl || 0;
      }

      // Q2: Files with Zone.Identifier — detail sample, MOST-RECENT-FIRST (the IR-relevant window).
      // The aggregates derived from this list (referrer/host roll-up, prioritized, clusters, lineage)
      // are therefore a recent sample of the full population; the UI labels them when capped. The
      // exact, full-population zone distribution + URL-coverage are computed separately in SQL below.
      let zoneIdFiles = [];
      if (zoneId && totalWithZoneId > 0) {
        const createdCol = created || `'' `;
        zoneIdFiles = db.prepare(
          `SELECT ${entry ? entry + " as entryNumber" : "rowid as entryNumber"}, ${fn} as fileName, ${ext ? ext + " as extension" : "'' as extension"}, ${pp ? pp + " as parentPath" : "'' as parentPath"}, ${createdCol} as created, ${zoneId} as zoneIdContents FROM data WHERE ${zoneId} IS NOT NULL AND ${zoneId} != '' ORDER BY ${created ? "sort_datetime(" + created + ")" : "rowid"} DESC LIMIT 2000`
        ).all();
        // Enrich with parsed zone data
        for (const f of zoneIdFiles) {
          const parsed = parseZoneId(f.zoneIdContents);
          f.zone = parsed.zone;
          f.zoneName = parsed.zoneName;
          f.referrerUrl = parsed.referrerUrl;
          f.hostUrl = parsed.hostUrl;
        }
      }

      // Q3: Downloaded executables (highest risk)
      let downloadedExecutables = [];
      if (zoneId && ext && totalWithZoneId > 0) {
        const suspExts = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".jar",".py"];
        const extPlaceholders = suspExts.map(() => "?").join(",");
        const createdCol = created || `''`;
        downloadedExecutables = db.prepare(
          `SELECT ${entry ? entry + " as entryNumber" : "rowid as entryNumber"}, ${fn} as fileName, ${ext} as extension, ${pp ? pp + " as parentPath" : "'' as parentPath"}, ${createdCol} as created, ${zoneId} as zoneIdContents FROM data WHERE ${zoneId} IS NOT NULL AND ${zoneId} != '' AND LOWER(${ext}) IN (${extPlaceholders}) ORDER BY ${created ? "sort_datetime(" + created + ")" : "rowid"} DESC LIMIT 500`
        ).all(...suspExts);
        for (const f of downloadedExecutables) {
          const parsed = parseZoneId(f.zoneIdContents);
          f.zone = parsed.zone;
          f.zoneName = parsed.zoneName;
          f.referrerUrl = parsed.referrerUrl;
          f.hostUrl = parsed.hostUrl;
        }
      }

      // Q4: ADS entries (limit 1000)
      let adsEntries = [];
      if (isAds && totalAdsEntries > 0) {
        const createdCol = created || `''`;
        adsEntries = db.prepare(
          `SELECT ${entry ? entry + " as entryNumber" : "rowid as entryNumber"}, ${fn} as fileName, ${pp ? pp + " as parentPath" : "'' as parentPath"}, ${createdCol} as created, ${fs ? fs + " as fileSize" : "'' as fileSize"} FROM data WHERE ${isAds} = 'True' ORDER BY ${created ? "sort_datetime(" + created + ")" : "rowid"} ASC LIMIT 1000`
        ).all();
      }

      // Q5: Top directories with downloaded files
      let topDownloadDirs = [];
      if (zoneId && pp && totalWithZoneId > 0) {
        topDownloadDirs = db.prepare(`SELECT ${pp} as path, COUNT(*) as count FROM data WHERE ${zoneId} IS NOT NULL AND ${zoneId} != '' GROUP BY ${pp} ORDER BY count DESC LIMIT 20`).all();
      }

      // Q6: Non-Zone stream carriers — files that carry a named alternate data stream that is NOT
      // (only) Zone.Identifier. On a raw $MFT the parser exposes HasAds but not the non-Zone stream
      // name/content, so this is the only knowable surface for the classic "malware hidden in
      // file.txt:evil" tradecraft (T1564.004); on MFTECmd CSV it complements the per-stream IsAds rows.
      // Ordered most-recent-first for IR relevance.
      let streamCarriers = [];
      let totalStreamCarriers = 0;
      let totalAdsExecStreams = 0;
      let nonBenignStreamCarriers = 0; // carriers excluding rows whose only stream is a known-benign OS/app stream
      if (hasAds) {
        const noZone = zoneId ? "AND (" + zoneId + " IS NULL OR " + zoneId + " = '')" : "";
        totalStreamCarriers = db.prepare("SELECT COUNT(*) as cnt FROM data WHERE " + hasAds + " = 'True' " + noZone + " " + notDir).get()?.cnt || 0;
        if (totalStreamCarriers > 0) {
          const orderBy = created ? `sort_datetime(${created}) DESC` : "rowid DESC";
          streamCarriers = db.prepare(
            "SELECT " + (entry ? entry + " as entryNumber" : "rowid as entryNumber") + ", " + (fn ? fn + " as fileName" : "'' as fileName") + ", " + (ext ? ext + " as extension" : "'' as extension") + ", " + (pp ? pp + " as parentPath" : "'' as parentPath") + ", " + (created ? created + " as created" : "'' as created") + ", " + (fs ? fs + " as fileSize" : "'' as fileSize") + ", " + (siFn ? siFn + " as siFn" : "'' as siFn") + ", " + (uSec ? uSec + " as uSecZeros" : "'' as uSecZeros") + ", " + (adsStreamsCol ? adsStreamsCol + " as adsStreams" : "'' as adsStreams") + " FROM data WHERE " + hasAds + " = 'True' " + noZone + " " + notDir + " ORDER BY " + orderBy + " LIMIT 500"
          ).all();
          // T5: parse the parser's "<flag>name(size)" descriptors so the analyst sees the actual stream
          // NAME(s) (e.g. invoice.pdf -> "payload.exe"), not just "has a stream". The leading flag char is
          // ALWAYS present ('!' = resident PE/MZ content, else not), so it cannot be forged by a stream
          // name that begins with '!'. exec-like = resident PE OR exec/script stream-name extension, minus
          // known-benign OS/app streams. large = a sizeable hidden stream (a real hidden EXE is usually
          // non-resident, so its bytes can't be sniffed — surface the size as an independent signal).
          const extOf = (n) => { const d = String(n || "").lastIndexOf("."); return d > 0 ? String(n).slice(d).toLowerCase() : ""; };
          const LARGE_STREAM = 100 * 1024;
          for (const f of streamCarriers) {
            f.streams = String(f.adsStreams || "").split("|").filter(Boolean).map((tok) => {
              const m = tok.match(/^(.)([\s\S]*)\((\d+|\?)\)$/);
              const execContent = m ? m[1] === "!" : false;
              const name = m ? m[2] : tok.replace(/^[!.]/, "");
              const size = m && m[3] !== "?" ? Number(m[3]) : null;
              const benign = BENIGN_STREAMS.has(name.toLowerCase());
              return { name, size, execContent, benign, large: !benign && size != null && size >= LARGE_STREAM, execLike: !benign && (execContent || EXEC_EXTS.has(extOf(name))) };
            });
            f.execLike = f.streams.some((s) => s.execLike);
            // T6: $SI-reliability — the carrier's created/ordering rests on $SI (Created0x10), which is
            // user-settable. Flag rows whose $SI looks timestomped ($SI predates $FN, or sub-second
            // zeroed) so the stream's apparent timing is treated as unreliable until corroborated.
            f.siSuspect = String(f.siFn) === "True" || String(f.uSecZeros) === "True";
            delete f.siFn; delete f.uSecZeros;
            delete f.adsStreams;
          }
          // Full-population count of exec-like carriers (resident-PE '!' marker OR an exec/script stream
          // extension), independent of the LIMIT-500 detail sample so the headline is exact, not a floor.
          if (adsStreamsCol) {
            const conds = [`${adsStreamsCol} LIKE '!%'`, `${adsStreamsCol} LIKE '%|!%'`];
            for (const e of EXEC_EXTS) conds.push(`${adsStreamsCol} LIKE '%${e}(%'`);
            totalAdsExecStreams = db.prepare("SELECT COUNT(*) as cnt FROM data WHERE " + hasAds + " = 'True' " + noZone + " " + notDir + " AND (" + conds.join(" OR ") + ")").get()?.cnt || 0;
          } else {
            totalAdsExecStreams = streamCarriers.filter((f) => f.execLike).length;
          }
          // Benign-excluded carrier count for the verdict: subtract single-stream rows whose only stream
          // is a known-benign OS/app stream (WofCompressedData, SmartScreen, …) so they don't inflate
          // severity or read as a finding. Conservative — only single-stream pure-benign rows (the
          // dominant benign case); rare multi-stream-benign rows stay counted. Falls back to the raw
          // count when stream names aren't enumerable (MFTECmd / older tabs).
          nonBenignStreamCarriers = totalStreamCarriers;
          if (adsStreamsCol) {
            try {
              const adsCountCol = col("AdsStreamCount");
              const benignConds = [...BENIGN_STREAMS].map((n) => `${adsStreamsCol} LIKE '.${n}(%'`);
              const benignOnly = db.prepare("SELECT COUNT(*) as cnt FROM data WHERE " + hasAds + " = 'True' " + noZone + " " + notDir + (adsCountCol ? " AND " + adsCountCol + " = '1'" : "") + " AND (" + benignConds.join(" OR ") + ")").get()?.cnt || 0;
              nonBenignStreamCarriers = Math.max(0, totalStreamCarriers - benignOnly);
            } catch { nonBenignStreamCarriers = totalStreamCarriers; }
          }
        }
      }

      // ── T6: $SI-reliability + forgery-resistant cross-artifact corroboration. ─────────────────
      // The non-Zone-ADS surface above is single-source $MFT, and its ordering/timing rests on $SI
      // (user-settable). (a) Flag the share of stream carriers whose $SI looks timestomped. (b) When a
      // USN ($J) companion is open, corroborate each carrier against NamedData*/StreamChange reasons
      // (stamped at the real NTFS operation — forgery-resistant). (c) When an EVTX companion is open,
      // corroborate against Sysmon EID 15 (FileCreateStreamHash) — the definitive ADS-creation event,
      // carrying the creating process + hash. Every companion access is wrapped in try/catch so a
      // companion failure never breaks the MFT result.
      const correlation = { usnAvailable: false, evtxAvailable: false, usnNamedStreamTotal: 0, evtxStreamCreateTotal: 0, carriersChecked: 0, carriersUsnCorroborated: 0, carriersEvtxCorroborated: 0, motwCorroborated: 0 };
      const siReliability = { available: !!(siFn || uSec), suspectStreamCarriers: 0, totalStreamCarriers, note: "" };

      // (a) full-population count of $SI-suspect carriers (independent of the LIMIT-500 detail sample).
      if ((siFn || uSec) && hasAds && totalStreamCarriers > 0) {
        try {
          const noZone = zoneId ? `AND (${zoneId} IS NULL OR ${zoneId} = '')` : "";
          const susConds = [];
          if (siFn) susConds.push(`${siFn} = 'True'`);
          if (uSec) susConds.push(`${uSec} = 'True'`);
          siReliability.suspectStreamCarriers = db.prepare("SELECT COUNT(*) as cnt FROM data WHERE " + hasAds + " = 'True' " + noZone + " " + notDir + " AND (" + susConds.join(" OR ") + ")").get()?.cnt || 0;
          if (siReliability.suspectStreamCarriers > 0) siReliability.note = `${siReliability.suspectStreamCarriers} of ${totalStreamCarriers} stream carrier(s) have $SI timestamps that look timestomped ($SI<$FN or sub-second-zeroed) — their stream timing is unreliable; corroborate with USN/EVTX.`;
        } catch { /* SI columns absent or unreadable — leave 0 */ }
      } else if (!siFn && !uSec) {
        siReliability.note = "$SI<$FN / uSecZeros columns not present on this tab — per-row $SI-reliability not assessable.";
      }

      // Resolve companion contexts. Both are queried through small MATERIALIZED subsets so corroboration
      // is never O(carriers × companion): the named-stream USN rows go into an indexed TEMP table, and
      // the (rare) Sysmon EID 15 rows are parsed once into an in-memory leaf-filename map.
      let usnCtx = null, usnReady = false, usnUseEntry = false;
      if (usnMeta && usnMeta.db && usnMeta.colMap) {
        const uName = usnMeta.colMap["Name"], uTs = usnMeta.colMap["UpdateTimestamp"], uReasons = usnMeta.colMap["UpdateReasons"], uEntry = usnMeta.colMap["EntryNumber"];
        if (uName && uReasons) { usnCtx = { db: usnMeta.db, name: uName, ts: uTs, reasons: uReasons, entry: uEntry }; correlation.usnAvailable = true; }
      }
      let evtxCtx = null;
      if (evtxMeta && evtxMeta.db) {
        try {
          const { _rwResolveEvtxCols } = require("./ransomware");
          const c = _rwResolveEvtxCols(evtxMeta);
          // EID 15 (FileCreateStreamHash) carries the streamed path in TargetFilename — its own column on
          // raw exploded EVTX (NOT in textCols), or embedded in the payload blob on EvtxECmd/Hayabusa.
          // Include both so the leaf-filename extraction below works across formats.
          const headers = evtxMeta.headers || [];
          const tfHeader = headers.find((h) => /^target_?filename$/i.test(h));
          const tf = tfHeader && evtxMeta.colMap ? evtxMeta.colMap[tfHeader] : null;
          const blobCols = [];
          if (tf) blobCols.push(tf);
          if (c && c.textCols && c.textCols.length) blobCols.push(...c.textCols);
          else if (c && c.proc && c.proc.image) blobCols.push(c.proc.image);
          if (c && c.eid && blobCols.length) {
            const blob = blobCols.map((x) => `COALESCE(${x},'')`).join("||' '||");
            evtxCtx = { db: evtxMeta.db, eid: c.eid, ts: c.ts, channel: c.channel, blob };
            correlation.evtxAvailable = true;
          }
        } catch { /* ransomware helper unavailable — skip EVTX */ }
      }

      if (usnCtx || evtxCtx) {
        const NAMED_STREAM = usnCtx ? `(${usnCtx.reasons} LIKE '%NamedDataExtend%' OR ${usnCtx.reasons} LIKE '%NamedDataOverwrite%' OR ${usnCtx.reasons} LIKE '%NamedDataTruncation%' OR ${usnCtx.reasons} LIKE '%StreamChange%')` : "";

        // (b) USN landscape + indexed TEMP subset. The named-stream rows are a tiny fraction of $J, so
        // materialize them ONCE into an indexed temp table — per-carrier lookup is then an indexed
        // equality, not a full-journal scan. (DROP+CREATE so a re-run on the same connection refreshes.)
        usnUseEntry = !!(usnCtx && usnCtx.entry && entry); // entry-match only when MFT EntryNumber is real
        if (usnCtx) {
          try { correlation.usnNamedStreamTotal = usnCtx.db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${NAMED_STREAM}`).get()?.cnt || 0; } catch { correlation.usnNamedStreamTotal = 0; }
          if (correlation.usnNamedStreamTotal > 0) {
            try {
              usnCtx.db.exec(`DROP TABLE IF EXISTS ads_usn`);
              usnCtx.db.exec(`CREATE TEMP TABLE ads_usn AS SELECT ${usnCtx.name} AS n, ${usnCtx.entry || "''"} AS e, ${usnCtx.ts || "''"} AS t, ${usnCtx.reasons} AS r FROM data WHERE ${NAMED_STREAM}`);
              usnCtx.db.exec(`CREATE INDEX ads_usn_n ON ads_usn(n)`);
              usnReady = true;
            } catch { usnReady = false; }
          }
        }
        const usnStmt = usnReady ? (() => { try { return usnCtx.db.prepare(`SELECT COUNT(*) as cnt, MIN(t) as firstTs, MAX(t) as lastTs FROM ads_usn WHERE n = ?${usnUseEntry ? " AND e = ?" : ""}`); } catch { return null; } })() : null;

        // (c) EVTX landscape + parsed map. EID 15 is rare relative to the full log; pull the (Sysmon-
        // channel-scoped) subset ONCE and extract the streamed leaf filename from each TargetFilename
        // (`...<sep><leaf>:<stream>` — path separator before, stream colon after), keyed by lowercased
        // leaf. This is path- AND colon-anchored, so a bare process path, a same-named file in another
        // directory, or an embedded stem (weekly_report.docx ⊅ report.docx) cannot falsely corroborate.
        const chanClause = evtxCtx && evtxCtx.channel ? ` AND LOWER(${evtxCtx.channel}) LIKE '%sysmon%'` : "";
        const e15Map = new Map();
        if (evtxCtx) {
          try { correlation.evtxStreamCreateTotal = evtxCtx.db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE CAST(${evtxCtx.eid} AS TEXT) = '15'${chanClause}`).get()?.cnt || 0; } catch { correlation.evtxStreamCreateTotal = 0; }
          if (correlation.evtxStreamCreateTotal > 0) {
            try {
              const EVTX_CAP = 200000;
              const rows = evtxCtx.db.prepare(`SELECT ${evtxCtx.blob} AS b${evtxCtx.ts ? `, ${evtxCtx.ts} AS ts` : ""} FROM data WHERE CAST(${evtxCtx.eid} AS TEXT) = '15'${chanClause} LIMIT ${EVTX_CAP}`).all();
              correlation.evtxScanned = rows.length;
              correlation.evtxCapped = correlation.evtxStreamCreateTotal > rows.length;
              const leafRe = /[\\/]([^\\/:"'\s]+):/g;
              for (const row of rows) {
                const b = String(row.b || "");
                leafRe.lastIndex = 0;
                let m; const seen = new Set();
                while ((m = leafRe.exec(b)) !== null) {
                  const leaf = m[1].toLowerCase();
                  if (seen.has(leaf)) continue;
                  seen.add(leaf);
                  let arr = e15Map.get(leaf); if (!arr) { arr = []; e15Map.set(leaf, arr); }
                  if (arr.length < 50) arr.push({ ts: row.ts || null, text: b.slice(0, 300) });
                }
              }
            } catch { /* EVTX subset unreadable — leave map empty */ }
          }
        }

        // Corroborate EVERY displayed carrier (cheap now): indexed USN lookup + O(1) leaf-map lookup.
        if (usnStmt || e15Map.size) {
          for (const f of streamCarriers) {
            f.corrChecked = true;
            correlation.carriersChecked++;
            if (usnStmt && f.fileName) {
              try {
                const r = usnUseEntry ? usnStmt.get(f.fileName, f.entryNumber) : usnStmt.get(f.fileName);
                if (r && r.cnt > 0) {
                  f.usnCorroboration = { namedStreamOps: r.cnt, firstTs: r.firstTs || null, lastTs: r.lastTs || null, strong: usnUseEntry };
                  correlation.carriersUsnCorroborated++;
                }
              } catch { /* per-carrier USN best-effort */ }
            }
            if (e15Map.size && f.fileName) {
              const hits = e15Map.get(String(f.fileName).toLowerCase());
              if (hits && hits.length) {
                f.evtxCorroboration = { streamCreates: hits.length, samples: hits.slice(0, 2).map((h) => ({ text: (h.text || "").trim(), ts: h.ts || null })).filter((x) => x.text) };
                correlation.carriersEvtxCorroborated++;
              }
            }
          }
        }
      }

      // Referrer + host roll-up from the (most-recent) detail sample. zoneBreakdown is computed in SQL
      // over the full population above. Host folds onto the NORMALIZED host (the delivery-domain IOC)
      // rather than the full URL, so https://evil.com/a.exe and https://evil.com/b.exe aggregate.
      const referrerCounts = {};
      const hostCounts = {};
      for (const f of zoneIdFiles) {
        if (f.referrerUrl) referrerCounts[f.referrerUrl] = (referrerCounts[f.referrerUrl] || 0) + 1;
        const h = hostFromUrl(f.hostUrl || f.referrerUrl);
        if (h) hostCounts[h] = (hostCounts[h] || 0) + 1;
      }
      const referrerUrls = Object.entries(referrerCounts).map(([url, count]) => ({ url, count })).sort((a, b) => b.count - a.count).slice(0, 30);
      const hostUrls = Object.entries(hostCounts).map(([url, count]) => ({ url, count })).sort((a, b) => b.count - a.count).slice(0, 30);

      // JS post-processing: prioritization, source clustering, archive lineage, MOTW heuristics, ADS anomalies
      const prioritizedDownloads = zoneIdFiles.map((f) => {
        const extLower = String(f.extension || "").toLowerCase();
        const host = hostFromUrl(f.hostUrl || f.referrerUrl);
        const internalHost = isInternalHost(host);
        const sourceType = inferTransferSource(f.referrerUrl, f.hostUrl);
        const reasons = [];
        let riskScore = 0;
        if (EXEC_EXTS.has(extLower)) { riskScore += 3; reasons.push("executable/script"); }
        else if (ARCHIVE_EXTS.has(extLower)) { riskScore += 2; reasons.push("archive/container"); }
        else if (OFFICE_EXTS.has(extLower)) { riskScore += 1; reasons.push("office/document"); }
        if (parentDirRisk(f.parentPath)) { riskScore += 1; reasons.push("user-writable location"); }
        if (internalHost) { riskScore += 2; reasons.push("internal-host download"); }
        if (f.zone === 3) { riskScore += 1; reasons.push("internet MOTW"); }
        if (f.zone === 1 && internalHost) { riskScore += 1; reasons.push("intranet MOTW"); }
        f.transferSource = sourceType;
        f.internalHost = internalHost;
        f.sourceHost = host;
        f.riskScore = riskScore;
        f.riskReasons = reasons;
        f.isArchive = ARCHIVE_EXTS.has(extLower);
        f.isExecutableLike = EXEC_EXTS.has(extLower);
        return f;
      }).sort((a, b) => (b.riskScore - a.riskScore) || String(a.created || "").localeCompare(String(b.created || "")));

      const clusterMap = new Map();
      for (const f of prioritizedDownloads) {
        const host = f.sourceHost || "(unknown)";
        const type = f.transferSource || "(unknown)";
        const key = `${host}||${type}`;
        const cur = clusterMap.get(key) || { host, transferSource: type, count: 0, internal: false, samplePaths: new Set(), sampleFiles: new Set() };
        cur.count++;
        cur.internal = cur.internal || !!f.internalHost;
        if (cur.samplePaths.size < 4 && f.parentPath) cur.samplePaths.add(f.parentPath);
        if (cur.sampleFiles.size < 4 && f.fileName) cur.sampleFiles.add(f.fileName);
        clusterMap.set(key, cur);
      }
      const sourceClusters = Array.from(clusterMap.values()).map((c) => ({
        host: c.host,
        transferSource: c.transferSource,
        count: c.count,
        internal: c.internal,
        samplePaths: Array.from(c.samplePaths),
        sampleFiles: Array.from(c.sampleFiles),
      })).sort((a, b) => b.count - a.count).slice(0, 20);

      const internalHosts = sourceClusters.filter((c) => c.internal).map((c) => ({ host: c.host, count: c.count, transferSource: c.transferSource })).sort((a, b) => b.count - a.count);

      const archiveDownloads = prioritizedDownloads.filter((f) => f.isArchive && f.created && f.parentPath);
      let archiveLineage = [];
      let motwSuspicious = [];
      if (archiveDownloads.length > 0 && fn && pp) {
        const dirs = Array.from(new Set(archiveDownloads.map((f) => f.parentPath).filter(Boolean))).slice(0, 50);
        const minTs = archiveDownloads.map((f) => parseTs(f.created)).filter(Boolean);
        const minCreated = minTs.length ? new Date(Math.min(...minTs) - 3600000).toISOString().slice(0, 19).replace("T", " ") : null;
        const maxCreated = minTs.length ? new Date(Math.max(...minTs) + 86400000).toISOString().slice(0, 19).replace("T", " ") : null;
        if (dirs.length > 0 && created && minCreated && maxCreated) {
          const dirPlaceholders = dirs.map(() => "?").join(",");
          const lineageRows = db.prepare(
            `SELECT ${entry ? entry + " as entryNumber" : "rowid as entryNumber"}, ${fn} as fileName, ${ext ? ext + " as extension" : "'' as extension"}, ${pp} as parentPath, ${created} as created, ${zoneId ? `${zoneId} as zoneIdContents` : "'' as zoneIdContents"} FROM data WHERE ${pp} IN (${dirPlaceholders}) AND ${created} IS NOT NULL AND ${created} != '' AND sort_datetime(${created}) >= sort_datetime(?) AND sort_datetime(${created}) <= sort_datetime(?) ${notDir} ORDER BY sort_datetime(${created}) ASC LIMIT 8000`
          ).all(...dirs, minCreated, maxCreated);
          const rowsByDir = new Map();
          for (const r of lineageRows) {
            if (!rowsByDir.has(r.parentPath)) rowsByDir.set(r.parentPath, []);
            rowsByDir.get(r.parentPath).push(r);
          }
          for (const arch of archiveDownloads) {
            const aTs = parseTs(arch.created);
            if (!aTs) continue;
            const candidates = (rowsByDir.get(arch.parentPath) || []).filter((r) => {
              if ((r.entryNumber || "") === (arch.entryNumber || "")) return false;
              const rTs = parseTs(r.created);
              if (!rTs || rTs < aTs || rTs > aTs + 30 * 60 * 1000) return false;
              const extLower = String(r.extension || "").toLowerCase();
              return EXEC_EXTS.has(extLower) || OFFICE_EXTS.has(extLower) || ARCHIVE_EXTS.has(extLower);
            });
            if (candidates.length === 0) continue;
            const children = candidates.slice(0, 12).map((r) => {
              const parsed = parseZoneId(r.zoneIdContents);
              const extLower = String(r.extension || "").toLowerCase();
              return {
                entryNumber: r.entryNumber,
                fileName: r.fileName,
                extension: r.extension,
                created: r.created,
                zoneName: parsed.zoneName,
                hasZoneId: !!parsed.zoneName,
                isExecutableLike: EXEC_EXTS.has(extLower),
              };
            });
            const motwLossChildren = children.filter((c) => c.isExecutableLike && !c.hasZoneId);
            archiveLineage.push({
              archiveEntry: arch.entryNumber,
              archiveName: arch.fileName,
              archivePath: arch.parentPath,
              archiveCreated: arch.created,
              sourceHost: arch.sourceHost || "",
              internalHost: !!arch.internalHost,
              childCount: children.length,
              children,
              motwLossCount: motwLossChildren.length,
            });
            for (const child of motwLossChildren) {
              motwSuspicious.push({
                archiveName: arch.fileName,
                archiveCreated: arch.created,
                archivePath: arch.parentPath,
                childName: child.fileName,
                childEntry: child.entryNumber,
                childCreated: child.created,
                sourceHost: arch.sourceHost || "",
                internalHost: !!arch.internalHost,
                reason: "archive had Zone.Identifier but extracted executable/script did not",
              });
            }
          }
          archiveLineage.sort((a, b) => (b.motwLossCount - a.motwLossCount) || (b.childCount - a.childCount));
          motwSuspicious.sort((a, b) => String(a.childCreated || "").localeCompare(String(b.childCreated || "")));
          // T6: corroborate likely MOTW strips against the USN journal. USN doesn't record the stream
          // NAME, but a NamedDataTruncation/StreamChange/NamedDataOverwrite on a child that LOST its
          // Zone.Identifier is forgery-resistant evidence the MOTW stream was actually removed/altered
          // (Indicator Removal — T1553.005), versus the file simply never having carried one.
          // Reuse the indexed ads_usn TEMP subset (built above) — the strip reasons are a subset of
          // NAMED_STREAM — so this is an indexed equality per child, not a full-journal scan per child.
          if (usnReady && motwSuspicious.length > 0) {
            try {
              const STRIP = `(r LIKE '%NamedDataTruncation%' OR r LIKE '%StreamChange%' OR r LIKE '%NamedDataOverwrite%')`;
              const stripStmt = usnCtx.db.prepare(`SELECT COUNT(*) as cnt, MAX(t) as lastTs FROM ads_usn WHERE n = ?${usnUseEntry ? " AND e = ?" : ""} AND ${STRIP}`);
              for (const m of motwSuspicious) {
                if (!m.childName) continue;
                try {
                  const r = usnUseEntry ? stripStmt.get(m.childName, m.childEntry) : stripStmt.get(m.childName);
                  if (r && r.cnt > 0) { m.usnStripCorroborated = true; m.usnStripOps = r.cnt; m.usnStripLastTs = r.lastTs || null; correlation.motwCorroborated++; }
                } catch { /* per-child best-effort */ }
              }
            } catch { /* USN subset unavailable — leave motwSuspicious uncorroborated */ }
          }
        }
      }

      const adsAnomalies = adsEntries.map((a) => {
        const streamMatch = String(a.fileName || "").match(STREAM_NAME_PAT);
        const streamName = streamMatch ? streamMatch[1] : "";
        const suspicious = !!streamName && !/^zone\.identifier$/i.test(streamName);
        const execLike = /\.(exe|dll|js|vbs|ps1|hta|bat|cmd|scr|lnk)$/i.test(streamName);
        return {
          ...a,
          streamName,
          suspicious,
          execLike,
        };
      }).filter((a) => a.suspicious).slice(0, 100);

      const riskyCount = prioritizedDownloads.filter((f) => f.riskScore >= 3).length;
      const archiveCount = prioritizedDownloads.filter((f) => f.isArchive).length;
      const execCount = prioritizedDownloads.filter((f) => f.isExecutableLike).length;
      const summaryParts = [];
      if (totalWithZoneId > 0) summaryParts.push(`${totalWithZoneId} MOTW-marked download${totalWithZoneId === 1 ? "" : "s"}`);
      if (archiveCount > 0) summaryParts.push(`${archiveCount} archive${archiveCount === 1 ? "" : "s"}`);
      if (motwSuspicious.length > 0) summaryParts.push(`${motwSuspicious.length} likely MOTW-loss child${motwSuspicious.length === 1 ? "" : "ren"}`);
      if (execCount > 0) summaryParts.push(`${execCount} executable/script download${execCount === 1 ? "" : "s"}`);
      if (internalHosts.length > 0) summaryParts.push(`source host${internalHosts.length === 1 ? "" : "s"} ${internalHosts.slice(0, 2).map((h) => h.host).join(", ")}`);
      if (totalStreamCarriers > 0) summaryParts.push(`${totalStreamCarriers.toLocaleString()} non-Zone stream carrier${totalStreamCarriers === 1 ? "" : "s"}${totalAdsExecStreams > 0 ? ` (${totalAdsExecStreams} exec-like)` : ""}`);
      // T6: surface forgery-resistant corroboration in the narrative (the headline can no longer
      // imply single-source $MFT is the whole story when companions confirm/deny it).
      if (correlation.usnNamedStreamTotal > 0) summaryParts.push(`USN: ${correlation.usnNamedStreamTotal.toLocaleString()} named-stream write${correlation.usnNamedStreamTotal === 1 ? "" : "s"}${correlation.carriersUsnCorroborated > 0 ? `, ${correlation.carriersUsnCorroborated} carrier(s) corroborated` : ""}`);
      if (correlation.evtxStreamCreateTotal > 0) summaryParts.push(`EVTX: ${correlation.evtxStreamCreateTotal.toLocaleString()} Sysmon EID 15 stream-create${correlation.evtxStreamCreateTotal === 1 ? "" : "s"}${correlation.carriersEvtxCorroborated > 0 ? `, ${correlation.carriersEvtxCorroborated} carrier(s) corroborated` : ""}`);
      const summary = {
        narrative: summaryParts.length > 0 ? summaryParts.join(" • ") : "No download-forensics story available",
        riskyCount,
        archiveCount,
        execCount,
        motwLossCount: motwSuspicious.length,
        internalHostCount: internalHosts.length,
        streamCarrierCount: totalStreamCarriers,
        execStreamCount: totalAdsExecStreams,
        siSuspectCount: siReliability.suspectStreamCarriers,
        usnCorroborated: correlation.carriersUsnCorroborated,
        evtxCorroborated: correlation.carriersEvtxCorroborated,
        motwStripCorroborated: correlation.motwCorroborated,
      };

      return {
        totalWithAds,
        totalAdsEntries,
        totalWithZoneId,
        downloadedExecutables,
        zoneIdFiles,
        adsEntries,
        topDownloadDirs,
        zoneBreakdown,
        zoneNoUrlCount,
        referrerUrls,
        hostUrls,
        prioritizedDownloads: prioritizedDownloads.slice(0, 250),
        archiveLineage: archiveLineage.slice(0, 40),
        motwSuspicious: motwSuspicious.slice(0, 60),
        internalHosts,
        sourceClusters,
        adsAnomalies,
        streamCarriers,
        totalStreamCarriers,
        totalAdsExecStreams,
        correlation,
        siReliability,
        verdict: _buildAdsVerdict({ totalWithZoneId, totalStreamCarriers, nonBenignStreamCarriers, totalAdsExecStreams, execCount, motwSuspicious, internalHosts, zoneBreakdown, correlation, siReliability, hasAdsStreams: !!adsStreamsCol, isAdsCol: !!isAds }),
        summary,
      };
    } catch (err) {
      return { ...empty, error: err.message };
    }
  }

module.exports = { analyzeADS, _buildAdsVerdict };
