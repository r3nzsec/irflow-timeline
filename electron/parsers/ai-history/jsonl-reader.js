/**
 * ai-history/jsonl-reader.js — bounded streaming reader for untrusted JSONL.
 *
 * readline.createInterface buffers an entire line into one string before emitting it, so a
 * subject-controlled session file with one multi-gigabyte (or newline-free) line buffers the
 * whole file into heap and can OOM the worker. This reader caps per-line size: lines over the
 * cap are skipped (counted in parseStats.errors) without ever being fully materialized, so peak
 * memory is bounded by maxLineBytes + one read chunk regardless of input.
 */

const fs = require("fs");
const path = require("path");

// Current Claude Cowork transcripts can contain legitimate detached/tool-result records above
// 16MB (18.8MB observed in the live 2026 schema). Keep ingestion bounded while allowing those
// records to reach makeRow(), which independently caps retained FullText/tool evidence to 1MB.
const DEFAULT_MAX_LINE_BYTES = 32 * 1024 * 1024;
const READ_CHUNK_BYTES = 1 << 20; // 1MB

function parseSourceStats(parseStats, filePath) {
  if (!parseStats || !filePath) return null;
  if (!parseStats.bySource) parseStats.bySource = {};
  const sourceFile = path.resolve(filePath);
  if (!parseStats.bySource[sourceFile]) {
    parseStats.bySource[sourceFile] = {
      sourceFile,
      physicalLines: 0,
      deliveredLines: 0,
      parsedJsonLines: 0,
      errors: 0,
      oversizedLines: 0,
      malformedLines: 0,
      handlerErrors: 0,
      readErrors: 0,
    };
  }
  return parseStats.bySource[sourceFile];
}

/**
 * Stream a text file line-by-line without materializing a line above maxLineBytes. Every newline
 * advances the physical line number, including blank, malformed, and oversized lines. The byte
 * offset is measured from the beginning of the source file.
 * @param {string} filePath
 * @param {(line:string, lineNumber:number, sourceLocation:{byteOffset:number,byteLength:number}) => void} onLine
 * @param {{ parseStats?: {errors:number}, maxLineBytes?: number }} [options]
 */
async function readLinesBounded(filePath, onLine, options = {}) {
  const parseStats = options.parseStats || null;
  const sourceStats = parseSourceStats(parseStats, filePath);
  const checkAbort = typeof options.checkAbort === "function"
    ? options.checkAbort
    : (typeof parseStats?.checkAbort === "function" ? parseStats.checkAbort : () => {});
  const maxLineBytes = options.maxLineBytes || DEFAULT_MAX_LINE_BYTES;
  const stream = fs.createReadStream(filePath, { highWaterMark: READ_CHUNK_BYTES });
  let parts = [];
  let bufferedBytes = 0;
  let dropping = false;
  let lineNumber = 0;
  let lineStartOffset = 0;
  let chunkStartOffset = 0;

  const increment = (name) => {
    if (!parseStats) return;
    parseStats[name] = (parseStats[name] || 0) + 1;
    if (sourceStats) sourceStats[name] = (sourceStats[name] || 0) + 1;
  };
  const append = (segment) => {
    if (dropping || !segment.length) return;
    if (bufferedBytes + segment.length > maxLineBytes) {
      increment("errors");
      increment("oversizedLines");
      parts = [];
      bufferedBytes = 0;
      dropping = true;
      return;
    }
    parts.push(segment);
    bufferedBytes += segment.length;
  };
  const emit = (lineEndOffset) => {
    lineNumber += 1;
    if (sourceStats) sourceStats.physicalLines += 1;
    const sourceLocation = {
      byteOffset: lineStartOffset,
      byteLength: Math.max(0, lineEndOffset - lineStartOffset),
    };
    if (!dropping) {
      const line = parts.length === 0 ? "" : Buffer.concat(parts, bufferedBytes).toString("utf8");
      try {
        onLine(line, lineNumber, sourceLocation);
        if (sourceStats) sourceStats.deliveredLines += 1;
      } catch {
        increment("errors");
        increment("handlerErrors");
      }
    }
    parts = [];
    bufferedBytes = 0;
    dropping = false;
  };

  try {
    for await (const chunk of stream) {
      checkAbort();
      if (parseStats) parseStats.bytesRead = (parseStats.bytesRead || 0) + chunk.length;
      if (sourceStats) sourceStats.bytesRead = (sourceStats.bytesRead || 0) + chunk.length;
      let segmentStart = 0;
      for (let i = 0; i < chunk.length; i++) {
        if (chunk[i] !== 0x0a) continue;
        append(chunk.subarray(segmentStart, i));
        emit(chunkStartOffset + i);
        lineStartOffset = chunkStartOffset + i + 1;
        segmentStart = i + 1;
      }
      append(chunk.subarray(segmentStart));
      chunkStartOffset += chunk.length;
    }
  } catch (error) {
    increment("errors");
    increment("readErrors");
    throw error;
  }
  checkAbort();
  if (lineStartOffset < chunkStartOffset || dropping || bufferedBytes > 0) emit(chunkStartOffset);
}

/**
 * Stream a JSONL file line-by-line, JSON-parsing each line and invoking
 * onLine(obj, lineNumber, sourceLocation). A parse or handler failure skips only that physical line.
 * @param {string} filePath
 * @param {(obj:any, lineNumber:number, sourceLocation:{byteOffset:number,byteLength:number}) => void} onLine
 * @param {{ parseStats?: {errors:number}, maxLineBytes?: number }} [options]
 */
async function readJsonlBounded(filePath, onLine, options = {}) {
  const parseStats = options.parseStats || null;
  const sourceStats = parseSourceStats(parseStats, filePath);
  await readLinesBounded(filePath, (line, lineNumber, sourceLocation) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let obj;
    try { obj = JSON.parse(trimmed); } catch {
      if (parseStats) {
        parseStats.errors = (parseStats.errors || 0) + 1;
        parseStats.malformedLines = (parseStats.malformedLines || 0) + 1;
        sourceStats.errors += 1;
        sourceStats.malformedLines += 1;
      }
      return;
    }
    if (sourceStats) sourceStats.parsedJsonLines += 1;
    onLine(obj, lineNumber, sourceLocation);
  }, options);
}

module.exports = { readLinesBounded, readJsonlBounded, DEFAULT_MAX_LINE_BYTES };
