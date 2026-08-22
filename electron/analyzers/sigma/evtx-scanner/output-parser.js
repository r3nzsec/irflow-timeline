const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { getKvExtractableFields, isDfirKvField } = require("../../../utils/dfir-event-fields");

// Hard cap on per-event rows collected from a single scan to prevent OOM with broad rules.
const MAX_EVENT_ROWS = 100000;

// Backward-compatible export name. The values now come from the shared field registry.
const DFIR_KV_FIELDS = new Set(getKvExtractableFields());

function normalizeLevel(level) {
  const normalized = String(level || "medium").toLowerCase();
  // Hayabusa abbreviates level names in its output depending on version and profile
  // ("crit"/"med"/"info"). Left unmapped they become their own severity buckets, so a
  // critical detection lands under a "crit" level the severity histogram never counts.
  if (normalized === "crit") return "critical";
  if (normalized === "med") return "medium";
  if (normalized === "info") return "informational";
  return normalized;
}

// Returns true if the file ends on a newline (i.e. a complete final record).
// A Hayabusa output file cut off mid-write (process crash/kill) typically ends
// without one — combined with a short/unparseable last record, that flags a
// truncated tail so the scan can warn instead of silently undercounting.
function fileEndsWithNewline(filePath) {
  let fd;
  try {
    const size = fs.statSync(filePath).size;
    if (size === 0) return true;
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(1);
    fs.readSync(fd, buf, 0, 1, size - 1);
    return buf[0] === 0x0a;
  } catch {
    return true; // can't tell — don't raise a false alarm
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
  }
}

function parseCsvLine(line) {
  const fields = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

function extractDfirKvFields(row, blob) {
  if (!blob) return row;
  if (typeof blob === "object") {
    for (const [key, val] of Object.entries(blob)) {
      if (key && val != null && !row[key] && isDfirKvField(key)) {
        row[key] = String(val);
      }
    }
    return row;
  }

  const kvParts = String(blob).split(/\s*¦\s*/);
  for (const kv of kvParts) {
    const sep = kv.indexOf(":");
    if (sep > 0 && sep < 30) {
      const key = kv.substring(0, sep).trim();
      const val = kv.substring(sep + 1).trim();
      if (key && val && val !== "-" && !row[key] && /^[A-Za-z][A-Za-z0-9_]*$/.test(key) && isDfirKvField(key)) {
        row[key] = val;
      }
    }
  }
  return row;
}

function buildRuleMatch({ ruleMatches, evtRow, ruleTitle, ruleId, ruleFile, level, channel, mitreTags, mitreTactics, otherTags, timestamp, computer }) {
  const matchKey = ruleId || ruleFile || ruleTitle;
  if (!ruleMatches.has(matchKey)) {
    ruleMatches.set(matchKey, {
      ruleId,
      ruleFile,
      title: ruleTitle,
      level,
      status: "stable",
      description: "",
      author: "",
      category: channel,
      mitre: [],
      tactics: [],
      tags: otherTags ? otherTags.split(",").map((tag) => tag.trim()).filter(Boolean) : [],
      falsepositives: [],
      count: 0,
      firstTs: timestamp,
      lastTs: timestamp,
      sampleRows: [],
      hosts: new Set(),
    });
    if (mitreTags) ruleMatches.get(matchKey).mitre = mitreTags.split(",").map((tag) => tag.trim()).filter(Boolean);
    if (mitreTactics) ruleMatches.get(matchKey).tactics = mitreTactics.split(",").map((tag) => tag.trim()).filter(Boolean);
  }

  const rm = ruleMatches.get(matchKey);
  rm.count++;
  if (timestamp && (!rm.firstTs || timestamp < rm.firstTs)) rm.firstTs = timestamp;
  if (timestamp && (!rm.lastTs || timestamp > rm.lastTs)) rm.lastTs = timestamp;
  if (computer) rm.hosts.add(computer.toUpperCase());
  if (rm.sampleRows.length < 5) rm.sampleRows.push(evtRow);
}

function createRowCollector({ resultStore, previewLimit, onProgress }) {
  const eventRows = [];
  const resultBuffer = [];
  let truncated = false;
  let matchedEvents = 0;

  const flush = () => {
    if (!resultStore || resultBuffer.length === 0) return;
    resultStore.addRows(resultBuffer.splice(0, resultBuffer.length));
  };

  const add = (evtRow) => {
    matchedEvents++;
    if (resultStore) {
      if (eventRows.length < previewLimit) eventRows.push(evtRow);
      resultBuffer.push(evtRow);
      if (resultBuffer.length >= 1000) flush();
      return;
    }
    if (eventRows.length < MAX_EVENT_ROWS) {
      eventRows.push(evtRow);
    } else if (!truncated) {
      truncated = true;
      onProgress?.({ phase: "parsing-results", text: `Row cap reached (${MAX_EVENT_ROWS.toLocaleString()}) - continuing aggregation only` });
    }
  };

  return {
    eventRows,
    add,
    flush,
    get truncated() { return truncated; },
    get matchedEvents() { return matchedEvents; },
  };
}

async function parseHayabusaCsv(csvPath, onProgress, scanJobId, options = {}) {
  const { resultStore = null, previewLimit = 2000, throwIfCancelled = null } = options;
  const fileSize = fs.statSync(csvPath).size;
  const endsClean = fileEndsWithNewline(csvPath);
  const collector = createRowCollector({ resultStore, previewLimit, onProgress });
  const ruleMatches = new Map();
  let colIdx = null;
  let lineNum = 0;
  let bytesRead = 0;
  let headerCount = 0;
  let lastDataColCount = 0;

  const rl = readline.createInterface({
    input: fs.createReadStream(csvPath, { encoding: "utf8", highWaterMark: 256 * 1024 }),
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    bytesRead += Buffer.byteLength(line, "utf8") + 1;
    lineNum++;

    if (lineNum === 1) {
      const headers = parseCsvLine(line);
      headerCount = headers.length;
      colIdx = {};
      headers.forEach((header, i) => { colIdx[header.trim()] = i; });
      continue;
    }
    if (!line.trim()) continue;

    const cols = parseCsvLine(line);
    lastDataColCount = cols.length;
    const get = (name) => (cols[colIdx[name]] || "").trim();
    const ruleTitle = get("RuleTitle");
    if (!ruleTitle) continue;

    const timestamp = get("Timestamp");
    const level = normalizeLevel(get("Level"));
    const computer = get("Computer");
    const channel = get("Channel");
    const eventId = get("EventID");
    const details = get("Details");
    const extraField = get("ExtraFieldInfo");
    const mitreTactics = get("MitreTactics");
    const mitreTags = get("MitreTags");
    const otherTags = get("OtherTags");
    const ruleFile = get("RuleFile");
    const ruleId = get("RuleID");
    const evtxFile = get("EvtxFile");
    const recordId = get("RecordID");

    const evtRow = {
      Timestamp: timestamp,
      Computer: computer,
      Channel: channel,
      EventID: eventId,
      Level: level,
      RuleID: ruleId,
      RuleTitle: ruleTitle,
      MITRE: [mitreTactics, mitreTags].filter(Boolean).join(", "),
      Details: details,
      ExtraFieldInfo: extraField,
      _SourceFile: evtxFile ? path.basename(evtxFile) : "",
      RecordID: recordId,
      RuleFile: ruleFile,
      Tags: otherTags,
    };

    extractDfirKvFields(evtRow, details);
    extractDfirKvFields(evtRow, extraField);
    collector.add(evtRow);
    buildRuleMatch({
      ruleMatches,
      evtRow,
      ruleTitle,
      ruleId,
      ruleFile,
      level,
      channel,
      mitreTags,
      mitreTactics,
      otherTags,
      timestamp,
      computer,
    });

    if (lineNum % 50000 === 0) {
      throwIfCancelled?.(scanJobId);
      const pct = fileSize > 0 ? Math.round((bytesRead / fileSize) * 100) : 0;
      onProgress?.({ phase: "parsing-results", text: `Parsing Hayabusa results - ${collector.matchedEvents.toLocaleString()} events (${pct}%)` });
    }
  }

  collector.flush();
  return {
    eventRows: collector.eventRows,
    ruleMatches,
    truncated: collector.truncated,
    eventRowCount: resultStore ? resultStore.rowCount : collector.eventRows.length,
    // File didn't end cleanly AND the last data row had fewer columns than the
    // header → the final record was cut off mid-write.
    truncatedTail: !endsClean && headerCount > 0 && lastDataColCount > 0 && lastDataColCount < headerCount,
  };
}

async function parseHayabusaJsonl(jsonlPath, levels, onProgress, scanJobId, options = {}) {
  const { resultStore = null, previewLimit = 2000, throwIfCancelled = null } = options;
  const fileSize = fs.statSync(jsonlPath).size;
  const endsClean = fileEndsWithNewline(jsonlPath);
  const collector = createRowCollector({ resultStore, previewLimit, onProgress });
  const ruleMatches = new Map();
  let lineNum = 0;
  let bytesRead = 0;
  let lastLineParseFailed = false;

  const rl = readline.createInterface({
    input: fs.createReadStream(jsonlPath, { encoding: "utf8", highWaterMark: 256 * 1024 }),
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    bytesRead += Buffer.byteLength(line, "utf8") + 1;
    lineNum++;
    if (!line.trim()) continue;

    let obj;
    try {
      obj = JSON.parse(line);
      lastLineParseFailed = false;
    } catch {
      lastLineParseFailed = true;
      continue;
    }

    const ruleTitle = obj.RuleTitle || obj.rule_title || "";
    if (!ruleTitle) continue;

    const timestamp = obj.Timestamp || obj.timestamp || "";
    const level = normalizeLevel(obj.Level || obj.level);
    const computer = obj.Computer || obj.computer || "";
    const channel = obj.Channel || obj.channel || "";
    const eventId = String(obj.EventID || obj.event_id || "");
    const mitreTactics = obj.MitreTactics || obj.mitre_tactics || "";
    const mitreTags = obj.MitreTags || obj.mitre_tags || "";
    const otherTags = obj.OtherTags || obj.other_tags || "";
    const ruleFile = obj.RuleFile || obj.rule_file || "";
    const ruleId = obj.RuleID || obj.rule_id || "";
    const evtxFile = obj.EvtxFile || obj.evtx_file || "";
    const recordId = String(obj.RecordID || obj.record_id || "");
    const details = obj.Details || obj.details || "";
    const extraField = obj.ExtraFieldInfo || obj.extra_field_info || "";

    const evtRow = {
      Timestamp: timestamp,
      Computer: computer,
      Channel: channel,
      EventID: eventId,
      Level: level,
      RuleTitle: ruleTitle,
      RuleID: ruleId,
      MITRE: [mitreTactics, mitreTags].filter(Boolean).join(", "),
      Details: typeof details === "object" ? JSON.stringify(details) : details,
      ExtraFieldInfo: typeof extraField === "object" ? JSON.stringify(extraField) : extraField,
      _SourceFile: evtxFile ? path.basename(evtxFile) : "",
      RecordID: recordId,
      RuleFile: ruleFile,
      Tags: otherTags,
    };

    extractDfirKvFields(evtRow, details);
    extractDfirKvFields(evtRow, extraField);
    collector.add(evtRow);
    buildRuleMatch({
      ruleMatches,
      evtRow,
      ruleTitle,
      ruleId,
      ruleFile,
      level,
      channel,
      mitreTags,
      mitreTactics,
      otherTags,
      timestamp,
      computer,
    });

    if (lineNum % 50000 === 0) {
      throwIfCancelled?.(scanJobId);
      const pct = fileSize > 0 ? Math.round((bytesRead / fileSize) * 100) : 0;
      onProgress?.({ phase: "parsing-results", text: `Parsing Hayabusa results - ${collector.matchedEvents.toLocaleString()} events (${pct}%)` });
    }
  }

  collector.flush();
  return {
    eventRows: collector.eventRows,
    ruleMatches,
    truncated: collector.truncated,
    eventRowCount: resultStore ? resultStore.rowCount : collector.eventRows.length,
    // File didn't end cleanly AND the last non-empty line wasn't valid JSON →
    // the final record was cut off mid-write.
    truncatedTail: !endsClean && lastLineParseFailed,
  };
}

function parseCsvFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split("\n").filter((line) => line.trim());
  if (lines.length < 1) return [];
  const headers = parseCsvLine(lines[0]);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCsvLine(lines[i]);
    const row = {};
    headers.forEach((header, idx) => { row[header.trim()] = (cols[idx] || "").trim(); });
    rows.push(row);
  }
  return rows;
}

module.exports = {
  MAX_EVENT_ROWS,
  DFIR_KV_FIELDS,
  normalizeLevel,
  parseCsvLine,
  parseCsvFile,
  extractDfirKvFields,
  parseHayabusaCsv,
  parseHayabusaJsonl,
};
