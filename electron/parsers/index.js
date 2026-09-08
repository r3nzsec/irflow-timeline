/**
 * parsers/index.js — Unified parser dispatcher for IRFlow Timeline
 *
 * Auto-detects file type and delegates to the appropriate format-specific parser.
 * Re-exports all public symbols so consumers can `require("./parsers")`.
 */

const path = require("path");

const { parseCSVLine, parseCSVStream, detectDelimiter } = require("./csv");
const { parseXLSXStream, parseXLSFile, getXLSXSheets } = require("./xlsx");
const { validatePlasoFile, parsePlasoFile } = require("./plaso");
const { parseEvtxFile } = require("./evtx");
const { isMftFile, parseMftFile, extractResidentData } = require("./mft");
const { isUsnJrnlFile, parseUsnJrnlFile } = require("./usn");
const { detectAiHistoryImport, parseAiHistoryImport } = require("./ai-history-import");

/**
 * Auto-detect file type and parse accordingly
 */
async function parseFile(filePath, tabId, db, onProgress, sheetName, fileSize) {
  // Pass fileSize hint to db.createTab for pragma scaling on large files
  if (fileSize) db._fileSizeHint = fileSize;
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".xls") {
    return parseXLSFile(filePath, tabId, db, onProgress, sheetName);
  }
  if (ext === ".xlsx" || ext === ".xlsm") {
    return parseXLSXStream(filePath, tabId, db, onProgress, sheetName);
  }
  if (ext === ".evtx") {
    return parseEvtxFile(filePath, tabId, db, onProgress);
  }
  if (ext === ".plaso" || ext === ".timeline") {
    const check = validatePlasoFile(filePath);
    if (ext === ".plaso" && !check.valid) throw new Error("Not a valid Plaso database (missing metadata table or format_version)");
    // .timeline files: if valid Plaso SQLite, parse as Plaso; otherwise fall through to CSV
    if (check.valid) return parsePlasoFile(filePath, tabId, db, onProgress);
    if (ext === ".timeline") { /* not Plaso — fall through to CSV below */ }
  }
  if (ext === ".mft") {
    return parseMftFile(filePath, tabId, db, onProgress);
  }
  if (ext === ".vhdx") {
    // A KAPE `--vhdx` package is a disk image, not a table. The triage flow reads the NTFS
    // volume inside it; falling through to CSV would parse the container header as a row.
    throw new Error("This is a VHDX disk image. Use File → Open Triage Collection… and pick the .vhdx to import the artifacts inside it.");
  }
  if (ext === ".vhd") {
    throw new Error("VHD (v1) images are not supported. Export the collection as VHDX (KAPE --vhdx) or open the collection folder with File → Open Triage Collection….");
  }
  if (ext === ".hve") {
    // Registry-hive decoding (Amcache / SYSTEM / SOFTWARE / NTUSER) is reserved for the 1.0.8
    // Super Timeline release. Fail closed rather than misparse a hive as a 1-column CSV.
    throw new Error("Registry hive (.hve) decoding is reserved for a future release.");
  }
  if (ext === ".pf") {
    // Direct Prefetch decoding is deferred from the 1.0.7 release scope. A dropped .pf would
    // otherwise be misparsed as a 1-column CSV, so fail closed instead.
    throw new Error("Prefetch (.pf) direct decoding is deferred in this release. Export parser CSV and open the CSV instead.");
  }
  // Auto-detect raw forensic files by name/magic bytes: $MFT ("FILE") and $J / USN Journal commonly
  // arrive with no extension or a generic ".dat", so the magic-byte probes — not the extension — are
  // authoritative. (Registry-hive decoding is reserved for the 1.0.8 Super Timeline release.)
  const baseName = path.basename(filePath).toUpperCase();
  if (!ext || ext === ".dat" || baseName.includes("MFT") || baseName.includes("USNJRNL") ||
      baseName === "$J") {
    // Check $J (USN Journal) first — filename-based detection
    if (isUsnJrnlFile(filePath)) {
      return parseUsnJrnlFile(filePath, tabId, db, onProgress);
    }
    // Check $MFT — "FILE" magic-byte detection
    if (isMftFile(filePath)) {
      return parseMftFile(filePath, tabId, db, onProgress);
    }
  }
  // Claude / Gemini CLI JSONL must not use the CSV parser (JSON keys become column headers).
  const aiHistory = detectAiHistoryImport(filePath);
  if (aiHistory) {
    return parseAiHistoryImport(filePath, tabId, db, onProgress, aiHistory);
  }

  if (ext === ".jsonl" || ext === ".json") {
    throw new Error(
      "This file looks like structured AI assistant data, not a delimited table. "
      + "Open the .claude, .codex, ChatGPT (com.openai.chat), or .gemini folder, "
      + "or use Tools → AI Artifacts…",
    );
  }

  // Default to CSV parsing (handles .csv, .tsv, .txt, .log, etc.)
  return parseCSVStream(filePath, tabId, db, onProgress);
}

module.exports = {
  parseCSVStream,
  parseXLSXStream,
  parseXLSFile,
  parsePlasoFile,
  parseEvtxFile,
  parseMftFile,
  isMftFile,
  extractResidentData,
  parseUsnJrnlFile,
  isUsnJrnlFile,
  validatePlasoFile,
  getXLSXSheets,
  parseFile,
  parseCSVLine,
  detectDelimiter,
};
