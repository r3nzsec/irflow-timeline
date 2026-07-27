/**
 * evtx.js — Windows EVTX event log parser
 *
 * Extracted from parser.js. Uses @ts-evtx/core for record iteration
 * and @ts-evtx/messages for optional message template resolution.
 */

const fs = require("fs");

const { dbg } = require("../logger");
const { getEvtxMessageSummaryFields, getEvtxWellKnownDataFields } = require("../utils/dfir-event-fields");

const BATCH_SIZE_DEFAULT = 100000;
const BATCH_SIZE_MAX_BYTES = 100 * 1024 * 1024; // ~100MB target max per batch
const FAST_MESSAGE_THRESHOLD_BYTES = 256 * 1024 * 1024;
const EVTX_FILE_HEADER_BYTES = 0x1000;
const EVTX_CHUNK_BYTES = 0x10000;

async function readFullyAt(handle, buffer, position) {
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, position + offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return offset;
}

/**
 * Iterate EVTX records without ever materializing the complete file.
 *
 * @ts-evtx/core's EvtxFile.open() calls fs.promises.readFile(), which fails at
 * Node's 2 GiB whole-file Buffer limit (and the dependency additionally rejects
 * files over 100 MiB after reading them). EVTX is natively split into a 4 KiB
 * file header followed by independent 64 KiB chunks, so read and parse exactly
 * one chunk at a time instead.
 */
async function* iterateEvtxRecords(filePath, core, knownSize = 0) {
  const { BinaryReader, FileHeader, ChunkHeader } = core;
  const handle = await fs.promises.open(filePath, "r");

  try {
    const stat = knownSize > 0 ? { size: knownSize } : await handle.stat();
    const totalBytes = Number(stat.size) || 0;
    const headerBytes = Buffer.alloc(EVTX_FILE_HEADER_BYTES);
    const headerRead = await readFullyAt(handle, headerBytes, 0);
    if (headerRead !== EVTX_FILE_HEADER_BYTES) {
      throw new Error("Invalid EVTX file: incomplete file header");
    }

    const header = new FileHeader(new BinaryReader(headerBytes), 0);
    if (!header.verify()) {
      throw new Error("Invalid EVTX file: header verification failed");
    }

    const declaredChunks = Math.max(0, Number(header.chunkCount()) || 0);
    const physicalChunks = Math.max(0, Math.floor((totalBytes - EVTX_FILE_HEADER_BYTES) / EVTX_CHUNK_BYTES));
    const chunkCount = Math.min(declaredChunks, physicalChunks);
    dbg("EVTX", "Using bounded chunk reader", {
      totalBytes,
      declaredChunks,
      physicalChunks,
      chunkCount,
      maxResidentReadBytes: EVTX_FILE_HEADER_BYTES + EVTX_CHUNK_BYTES,
    });

    const chunkBytes = Buffer.alloc(EVTX_CHUNK_BYTES);
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
      const position = EVTX_FILE_HEADER_BYTES + (chunkIndex * EVTX_CHUNK_BYTES);
      const chunkRead = await readFullyAt(handle, chunkBytes, position);
      if (chunkRead !== EVTX_CHUNK_BYTES) break;

      const chunk = new ChunkHeader(new BinaryReader(chunkBytes), 0);
      if (!chunk.checkMagic()) continue;

      const bytesRead = position + chunkRead;
      for (const record of chunk.records()) {
        yield { record, bytesRead, chunkIndex, chunkCount };
      }
    }
  } finally {
    await handle.close();
  }
}

// ── Cached EVTX message provider (created once, reused across all EVTX imports) ──
let _cachedMsgProvider = null;
let _msgProviderPromise = null;

async function getEvtxMessageProvider() {
  if (_cachedMsgProvider) return _cachedMsgProvider;
  if (_msgProviderPromise) return _msgProviderPromise;
  _msgProviderPromise = (async () => {
    try {
      const { SmartManagedMessageProvider } = await import("@ts-evtx/messages");
      const managed = new SmartManagedMessageProvider({ preload: true });
      await managed.ensure();
      _cachedMsgProvider = managed.provider; // SqliteMessageProvider with sync lookup
      dbg("EVTX", "Message provider cached globally");
      return _cachedMsgProvider;
    } catch {
      dbg("EVTX", "Message provider not available, skipping");
      return null;
    }
  })();
  return _msgProviderPromise;
}

const EVTX_FIXED_FIELDS = ["datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message"];
const EVTX_FIXED_COUNT = EVTX_FIXED_FIELDS.length;
const EVTX_FIXED_FIELD_SET = new Set(EVTX_FIXED_FIELDS);
const EVTX_MESSAGE_SUMMARY_FIELDS = getEvtxMessageSummaryFields();

// Well-known EventData field names that downstream analyzers (lateral movement,
// persistence, process tree, RDP session correlation) require but which the
// schema-discovery sample may miss when the first SAMPLE_LIMIT records of a log
// happen to be skewed toward a single event type.
//
// Real-world failure: a Security.evtx where the first ~14,000 records were all
// scheduled-task / object-access events (no IpAddress, no WorkstationName, no
// TargetUserName) caused the lateral movement analyzer to fail with
// "Cannot detect source host column" because the columns weren't in the schema
// at all — the discovered field set was finalized at record 500.
//
// Including these unconditionally costs a few empty TEXT columns on tabs that
// happen not to use them, which is cheap relative to silently dropping data
// from any later record that *does* carry them. The list is intentionally
// conservative — only fields that map to known column-detection patterns in
// the analyzers under electron/analyzers/.
const EVTX_WELL_KNOWN_DATA_FIELDS = getEvtxWellKnownDataFields();
const EVTX_LEVEL_MAP = { "0": "LogAlways", "1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose" };
const XML_ENTITIES = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" };
const decodeXmlEntities = (s) => s.replace(/&(?:amp|lt|gt|quot|apos|#(\d+)|#x([0-9a-fA-F]+));/g, (m, dec, hex) => {
  if (dec) return String.fromCharCode(parseInt(dec, 10));
  if (hex) return String.fromCharCode(parseInt(hex, 16));
  return XML_ENTITIES[m] || m;
});

/**
 * Fix byte-swapped UTF-16LE values from @ts-evtx/core BinXml rendering.
 * Some EVTX string substitution values come out with bytes in big-endian order:
 *   "㄀㌀" (char codes 3100, 3300) should be "13" (0031, 0033).
 * Detection: if all chars have their low byte as 0x00 (charCode & 0xFF === 0),
 * swap each char's bytes to get the correct ASCII/UTF-8 string.
 */
function fixByteSwappedUtf16(val) {
  if (!val || val.length < 1 || val.length > 10000) return val;
  // Quick check: does the string contain characters that look byte-swapped?
  // Byte-swapped ASCII has high byte = ASCII char, low byte = 0x00
  // e.g., '1' (0x31) becomes 0x3100 = '㄀'
  let swapped = 0;
  let total = 0;
  for (let i = 0; i < Math.min(val.length, 20); i++) {
    const c = val.charCodeAt(i);
    if (c > 127) { // non-ASCII
      total++;
      // Check if swapping bytes would produce a printable ASCII char
      const lo = c & 0xFF;
      const hi = (c >> 8) & 0xFF;
      if (lo === 0 && hi >= 0x20 && hi <= 0x7E) swapped++;
    }
  }
  // If most non-ASCII chars look byte-swapped, fix the whole string
  if (swapped > 0 && swapped >= total * 0.7 && total >= val.length * 0.5) {
    let fixed = "";
    for (let i = 0; i < val.length; i++) {
      const c = val.charCodeAt(i);
      if (c > 127 && (c & 0xFF) === 0) {
        fixed += String.fromCharCode((c >> 8) & 0xFF);
      } else {
        fixed += val[i];
      }
    }
    return fixed;
  }
  return val;
}

// Module-level regex constants for EVTX XML parsing — avoids recompilation per record
const EVTX_NAMED_DATA_RE = /<Data\s+Name="([^"]*)"[^>]*?>([^<]*)<\/Data>/gi;
const EVTX_UNNAMED_DATA_RE = /<Data>([^<]+)<\/Data>/g;
const EVTX_USERDATA_LEAF_RE = /<(\w+)>([^<]+)<\/\1>/g;

/**
 * Format a Windows event message template by substituting %1, %2, ... with data values.
 * Also replaces %n (newline) and %t (tab) with spaces for compact display.
 */
const EVTX_MSG_PARAM_RE = /%(\d+)(?:![^!]*!)?|%n|%t|%%/gi;
const EVTX_MULTI_SPACE_RE = /\s{2,}/g;

function formatEvtxMessage(template, dataValues) {
  if (!template) return "";
  // Single-pass: replace all %N params, %n, %t, %% in one regex callback
  const result = template.replace(EVTX_MSG_PARAM_RE, (match, num) => {
    if (num) {
      const idx = parseInt(num) - 1;
      return idx < dataValues.length ? dataValues[idx] : "";
    }
    const lower = match.toLowerCase();
    if (lower === "%n" || lower === "%t") return " ";
    if (match === "%%") return "%";
    return "";
  });
  return result.replace(EVTX_MULTI_SPACE_RE, " ").trim();
}

function isOpenElement(node, name) {
  return node?.constructor?.name === "OpenStartElementNode" && (!name || node.name === name);
}

function firstElement(node, name) {
  return (node?.children || []).find((child) => isOpenElement(child, name)) || null;
}

function formatStructuredValue(value, actual) {
  if (value == null) return "";
  let out;
  if (actual && typeof actual.formatForMessage === "function") {
    try { out = actual.formatForMessage(value); } catch { out = null; }
  }
  if (out == null) {
    if (value instanceof Date) out = value.toISOString();
    else if (typeof value === "bigint") out = value.toString();
    else if (Array.isArray(value)) out = value.map((v) => formatStructuredValue(v, actual)).join(", ");
    else out = String(value);
  }
  return fixByteSwappedUtf16(String(out));
}

function renderNodeText(node, substitutions, actual) {
  const parts = [];
  const visit = (n) => {
    const type = n?.constructor?.name;
    if (!type || type === "AttributeNode") return;
    if (type === "ValueTextNode") {
      parts.push(formatStructuredValue(n.data, actual));
      return;
    }
    if (type === "NormalSubstitutionNode" || type === "CompactSubstitutionNode" || type === "OptionalSubstitutionNode") {
      const idx = n.substitution_id ?? -1;
      parts.push(formatStructuredValue(idx >= 0 ? substitutions?.[idx] : "", actual));
      return;
    }
    for (const child of n.children || []) visit(child);
  };
  for (const child of node?.children || []) visit(child);
  return parts.join("");
}

function getAttributeValue(node, attrName, substitutions, actual) {
  const attr = (node?.children || []).find((child) =>
    child?.constructor?.name === "AttributeNode" &&
    String(child.name || child.attribute_name || "").toLowerCase() === attrName.toLowerCase()
  );
  if (!attr) return "";
  if (attr.value != null) return formatStructuredValue(attr.value, actual);
  return renderNodeText(attr, substitutions, actual);
}

function resolveLayoutValue(entry, substitutions, actual) {
  return fixByteSwappedUtf16((entry.parts || []).map((part) => {
    if (part.kind === "sub") return formatStructuredValue(substitutions?.[part.index], actual);
    return formatStructuredValue(part.text, actual);
  }).join(""));
}

function addLayoutToDataMap(layout, substitutions, actual, dataMap, dataValues, useParamForGenericData) {
  let paramIdx = dataValues.length;
  for (const entry of layout || []) {
    const value = resolveLayoutValue(entry, substitutions, actual);
    const name = entry.name ? String(entry.name) : "";
    let key = useParamForGenericData && (!name || name === "Data")
      ? `param${paramIdx}`
      : (name || `param${paramIdx}`);
    if (EVTX_FIXED_FIELD_SET.has(key)) key = `Data_${key}`;
    dataMap[key] = value;
    dataValues.push(value);
    paramIdx++;
  }
}

function buildCompactEvtxMessage(eventId, provider, dataMap) {
  const parts = [];
  for (const field of EVTX_MESSAGE_SUMMARY_FIELDS) {
    const value = dataMap[field];
    if (value != null && String(value).trim()) {
      parts.push(`${field}=${String(value).trim()}`);
      if (parts.length >= 8) break;
    }
  }
  const prefix = `Event ${eventId || "?"}${provider ? ` ${provider}` : ""}`;
  return parts.length > 0 ? `${prefix} | ${parts.join(" | ")}` : prefix;
}

/**
 * Parse a Windows EVTX file using @ts-evtx/core.
 * ESM-only library loaded via dynamic import() since app is CJS.
 *
 * Uses EvtxFile.open() + records() and extracts system/EventData fields from
 * parsed BXML templates directly. XML rendering remains as a fallback for
 * unusual records, but the hot path avoids constructing XML strings per row.
 *
 * Single-pass approach: buffer first 500 events for schema discovery,
 * finalize schema, flush buffer, then continue streaming.
 *
 * @param {string} filePath
 * @param {string} tabId
 * @param {TimelineDB} db
 * @param {Function} onProgress
 * @returns {Promise<{headers, rowCount, tsColumns, numericColumns}>}
 */
async function parseEvtxFile(filePath, tabId, db, onProgress) {
  const evtxCore = await import("@ts-evtx/core");
  let totalBytes = 0;
  try { totalBytes = fs.statSync(filePath).size; } catch { /* proceed with 0 */ }
  const SAMPLE_LIMIT = 500;
  const fastMessageMode = totalBytes >= FAST_MESSAGE_THRESHOLD_BYTES;

  // Large raw EVTX imports stay responsive by deferring expensive template
  // rendering. Structured fields remain available immediately.
  const msgProvider = fastMessageMode ? null : await getEvtxMessageProvider();
  const messageTemplateCache = new Map();

  const parseStructuredRecord = (record) => {
    const root = record.root();
    const templateInstance = root?.templateInstance?.();
    const actual = templateInstance?.getActualTemplate?.()
      || root?.chunk?.getActualTemplate?.(templateInstance?.template_offset);
    if (!actual?.rootElement) throw new Error("EVTX template unavailable");

    const substitutions = root.substitutions || [];
    const system = firstElement(actual.rootElement, "System");
    const providerNode = firstElement(system, "Provider");
    const eventIdNode = firstElement(system, "EventID");
    const levelNode = firstElement(system, "Level");
    const channelNode = firstElement(system, "Channel");
    const computerNode = firstElement(system, "Computer");

    let datetime = "";
    try {
      const d = record.timestampAsDate();
      if (!isNaN(d.getTime())) {
        datetime = d.toISOString().replace("T", " ").replace("Z", "");
      }
    } catch { /* leave empty */ }

    const recordId = String(record.recordNum());
    const eventId = renderNodeText(eventIdNode, substitutions, actual);
    const provider = getAttributeValue(providerNode, "Name", substitutions, actual);
    const levelNum = renderNodeText(levelNode, substitutions, actual);
    const level = EVTX_LEVEL_MAP[levelNum] || levelNum;
    const channel = renderNodeText(channelNode, substitutions, actual);
    const computer = renderNodeText(computerNode, substitutions, actual);

    const dataMap = {};
    const dataValues = [];
    const eventDataLayout = actual.getEventDataLayout(substitutions) || [];
    if (eventDataLayout.length > 0) {
      addLayoutToDataMap(eventDataLayout, substitutions, actual, dataMap, dataValues, true);
    } else if (typeof actual.getUserDataLayout === "function") {
      const userDataLayout = actual.getUserDataLayout(substitutions) || [];
      addLayoutToDataMap(userDataLayout, substitutions, actual, dataMap, dataValues, false);
    }

    let message = "";
    if (msgProvider && eventId && provider) {
      const cacheKey = `${provider}\u0000${eventId}`;
      let template = messageTemplateCache.get(cacheKey);
      if (template === undefined) {
        template = msgProvider.getMessageSync(provider, parseInt(eventId, 10)) || "";
        messageTemplateCache.set(cacheKey, template);
      }
      if (template) message = formatEvtxMessage(template, dataValues);
    }
    if (!message && fastMessageMode) message = buildCompactEvtxMessage(eventId, provider, dataMap);

    return {
      fixed: [datetime, recordId, eventId, provider, level, channel, computer, message],
      dataMap,
    };
  };

  const parseXmlRecord = (xml, record) => {
    // Timestamp from the Record object (always reliable)
    let datetime = "";
    try {
      const d = record.timestampAsDate();
      if (!isNaN(d.getTime())) {
        datetime = d.toISOString().replace("T", " ").replace("Z", "");
      }
    } catch { /* leave empty */ }

    const recordId = String(record.recordNum());

    // System fields from XML
    const eventIdMatch = xml.match(/<EventID[^>]*>(\d+)<\/EventID>/i);
    const eventId = eventIdMatch ? eventIdMatch[1] : "";

    const providerMatch = xml.match(/<Provider\s[^>]*Name="([^"]*)"/i);
    const provider = providerMatch ? providerMatch[1] : "";

    const levelMatch = xml.match(/<Level>(\d+)<\/Level>/i);
    const levelNum = levelMatch ? levelMatch[1] : "";
    const level = EVTX_LEVEL_MAP[levelNum] || levelNum;

    const channelMatch = xml.match(/<Channel>([^<]*)<\/Channel>/i);
    const channel = channelMatch ? channelMatch[1] : "";

    const computerMatch = xml.match(/<Computer>([^<]*)<\/Computer>/i);
    const computer = computerMatch ? computerMatch[1] : "";

    // EventData fields — collect both map (for columns) and ordered values (for message substitution)
    const dataMap = {};
    const dataValues = [];
    let paramIdx = 0;

    // Named: <Data Name="key">value</Data>
    EVTX_NAMED_DATA_RE.lastIndex = 0;
    let m;
    while ((m = EVTX_NAMED_DATA_RE.exec(xml)) !== null) {
      const val = fixByteSwappedUtf16(decodeXmlEntities(m[2]));
      dataMap[m[1]] = val;
      dataValues.push(val);
      paramIdx++;
    }

    // Unnamed: <Data>value</Data> (no Name attribute)
    EVTX_UNNAMED_DATA_RE.lastIndex = 0;
    while ((m = EVTX_UNNAMED_DATA_RE.exec(xml)) !== null) {
      const val = fixByteSwappedUtf16(decodeXmlEntities(m[1]));
      dataMap[`param${paramIdx}`] = val;
      dataValues.push(val);
      paramIdx++;
    }

    // UserData: extract leaf elements (some EVTX files use UserData instead of EventData)
    const userDataMatch = xml.match(/<UserData>([\s\S]*?)<\/UserData>/i);
    if (userDataMatch && paramIdx === 0) {
      const udContent = userDataMatch[1];
      EVTX_USERDATA_LEAF_RE.lastIndex = 0;
      while ((m = EVTX_USERDATA_LEAF_RE.exec(udContent)) !== null) {
        if (!dataMap[m[1]]) {
          const val = decodeXmlEntities(m[2]);
          dataMap[m[1]] = val;
          dataValues.push(val);
        }
      }
    }

    // Look up and format message from catalog
    let message = "";
    if (msgProvider && eventId && provider) {
      const cacheKey = `${provider}\u0000${eventId}`;
      let template = messageTemplateCache.get(cacheKey);
      if (template === undefined) {
        template = msgProvider.getMessageSync(provider, parseInt(eventId, 10)) || "";
        messageTemplateCache.set(cacheKey, template);
      }
      if (template) message = formatEvtxMessage(template, dataValues);
    }
    if (!message && fastMessageMode) message = buildCompactEvtxMessage(eventId, provider, dataMap);

    return {
      fixed: [datetime, recordId, eventId, provider, level, channel, computer, message],
      dataMap,
    };
  };

  const fieldSet = new Set();
  let earlyBuffer = [];
  let schemaFinalized = false;
  let headers = null;
  let colCount = 0;
  let batch = [];
  let batchSize = BATCH_SIZE_DEFAULT;
  let rowCount = 0;
  let lastProgress = 0;

  const buildRow = (parsed) => {
    const values = new Array(colCount);
    for (let f = 0; f < EVTX_FIXED_COUNT; f++) values[f] = parsed.fixed[f];
    for (let i = EVTX_FIXED_COUNT; i < colCount; i++) {
      const val = parsed.dataMap[headers[i]];
      values[i] = val != null ? val : "";
    }
    return values;
  };

  // Yield to event loop before starting to allow pending IPC to process
  await new Promise((r) => setImmediate(r));

  for await (const { record, bytesRead } of iterateEvtxRecords(filePath, evtxCore, totalBytes)) {
    let parsed;
    try {
      parsed = parseStructuredRecord(record);
    } catch {
      let xml;
      try { xml = record.renderXml(); } catch { continue; }
      parsed = parseXmlRecord(xml, record);
    }
    rowCount++;

    if (!schemaFinalized) {
      for (const key of Object.keys(parsed.dataMap)) fieldSet.add(key);
      earlyBuffer.push(parsed);

      if (rowCount >= SAMPLE_LIMIT) {
        // Union well-known fields into the discovered set so analyzers always
        // have the columns they need even when the early sample is skewed.
        for (const f of EVTX_WELL_KNOWN_DATA_FIELDS) fieldSet.add(f);
        const discoveredFields = [...fieldSet].sort();
        headers = [...EVTX_FIXED_FIELDS, ...discoveredFields];
        colCount = headers.length;
        db.createTab(tabId, headers);
        batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
        schemaFinalized = true;

        for (const buf of earlyBuffer) batch.push(buildRow(buf));
        earlyBuffer = null;

        if (batch.length >= batchSize) {
          db.insertBatchArrays(tabId, batch);
          batch = [];
        }
        if (onProgress) onProgress(rowCount, bytesRead, totalBytes);
      }
      continue;
    }

    batch.push(buildRow(parsed));
    if (batch.length >= batchSize) {
      db.insertBatchArrays(tabId, batch);
      batch = [];
      if (rowCount - lastProgress >= 10000) {
        lastProgress = rowCount;
        if (onProgress) onProgress(rowCount, bytesRead, totalBytes);
        // Yield to event loop periodically so IPC remains responsive
        await new Promise((r) => setImmediate(r));
      }
    }
  }

  // Handle files with fewer than SAMPLE_LIMIT events
  if (!schemaFinalized) {
    if (rowCount === 0) {
      // No events at all
      headers = [...EVTX_FIXED_FIELDS];
      colCount = headers.length;
      db.createTab(tabId, headers);
    } else {
      // Union well-known fields into the discovered set so analyzers always
      // have the columns they need even when the file has fewer than
      // SAMPLE_LIMIT records (and might still be missing a key field).
      for (const f of EVTX_WELL_KNOWN_DATA_FIELDS) fieldSet.add(f);
      const discoveredFields = [...fieldSet].sort();
      headers = [...EVTX_FIXED_FIELDS, ...discoveredFields];
      colCount = headers.length;
      db.createTab(tabId, headers);
      for (const buf of earlyBuffer) batch.push(buildRow(buf));
      earlyBuffer = null;
    }
  }

  if (batch.length > 0) {
    db.insertBatchArrays(tabId, batch);
  }
  // Null out large arrays to help GC before next import
  batch = null;
  earlyBuffer = null;

  if (onProgress) onProgress(rowCount, totalBytes, totalBytes);
  const result = db.finalizeImport(tabId);

  // Log memory usage after parsing
  const mem = process.memoryUsage();
  dbg("EVTX", `parseEvtxFile done`, { rowCount, heapUsedMB: Math.round(mem.heapUsed / 1048576), rssMB: Math.round(mem.rss / 1048576) });

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
    sourceFormat: "raw-evtx",
    evtxMessageMode: fastMessageMode ? "fast-structured" : (msgProvider ? "full" : "structured"),
    messagesDeferred: fastMessageMode,
  };
}

module.exports = {
  parseEvtxFile,
  _iterateEvtxRecords: iterateEvtxRecords,
  _readFullyAt: readFullyAt,
  EVTX_FILE_HEADER_BYTES,
  EVTX_CHUNK_BYTES,
};
