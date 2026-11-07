/**
 * csv.js — Streaming CSV/TSV parser for IRFlow Timeline
 *
 * Handles:
 *   - CSV (comma, tab, pipe delimited) via raw chunk processing
 *   - Progress callbacks for UI feedback
 *   - Batch insertion into SQLite (array-based, zero object allocation)
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { StringDecoder } = require("node:string_decoder");
const crypto = require("crypto");

// ── Debug trace logger (shared singleton — see logger.js) ─────────
const { dbg } = require("../logger");

const BATCH_SIZE_DEFAULT = 100000;
const BATCH_SIZE_MAX_BYTES = 100 * 1024 * 1024; // ~100MB target max per batch

// For very large files (>5GB — same threshold db.js uses for isLargeFile), accumulate a bigger
// per-batch buffer before flushing. Each insertBatchArrays() call is ONE transaction (BEGIN/COMMIT),
// and the per-row insert work is identical regardless of batch size — so a larger batch on a huge
// import amortises transaction-commit count (~2.5× fewer here) and improves B-tree page-cache
// locality. Worker threads inherit the ~16GB heap (main.js setFlagsFromString), and only one batch
// is live at a time, so the larger buffer is memory-safe. The 250k row ceiling bounds the wide-row
// case (small col count) and the byte target bounds the many-column case.
const LARGE_FILE_THRESHOLD_BYTES = 5 * 1024 * 1024 * 1024; // 5GB
const BATCH_SIZE_MAX_BYTES_LARGE = 256 * 1024 * 1024; // ~256MB target for >5GB files
const BATCH_SIZE_ROW_CEIL_LARGE = 250000; // row ceiling for >5GB files (vs 100k default)

const EST_BYTES_PER_CELL = 80; // rough per-cell size estimate for the byte-target → row-count conversion
const DB_HOST_PARAM_LIMIT = 32766; // SQLite SQLITE_MAX_VARIABLE_NUMBER — mirrors db.js multi-row INSERT chunk

/**
 * Compute the per-batch row count for an import, given the column count and total file size.
 * Pure + exported so the >5GB sizing is unit-testable without a multi-GB fixture.
 *
 * The result is rounded DOWN to a multiple of the DB's multi-row INSERT chunk
 * (floor(32766/cols)) so the per-batch remainder doesn't fall to the ~5-10×-slower single-row
 * INSERT path on every flush (mirrors db.js insertBatchArrays' multiRowCount).
 */
function computeImportBatchSize(colCount, totalBytes = 0) {
  const cols = Math.max(1, colCount | 0);
  const isLarge = totalBytes > LARGE_FILE_THRESHOLD_BYTES;
  const targetBytes = isLarge ? BATCH_SIZE_MAX_BYTES_LARGE : BATCH_SIZE_MAX_BYTES;
  const rowCeil = isLarge ? BATCH_SIZE_ROW_CEIL_LARGE : BATCH_SIZE_DEFAULT;

  // Adaptive: byte-target / estimated row size, clamped to [5k, rowCeil] BEFORE rounding.
  let batchSize = Math.max(5000, Math.min(rowCeil, Math.floor(targetBytes / (cols * EST_BYTES_PER_CELL))));

  // Round DOWN to a whole number of multi-row INSERT chunks (never below one chunk). For very
  // wide schemas the round-down can land a little under the 5000-row floor (e.g. ~4940) — that is
  // accepted (and matches the prior inline behaviour exactly); the floor only guards against tiny
  // batches, and one full INSERT chunk is still the hard minimum.
  const multiRowCount = Math.max(1, Math.floor(DB_HOST_PARAM_LIMIT / cols));
  if (multiRowCount > 1) {
    batchSize = Math.max(multiRowCount, Math.floor(batchSize / multiRowCount) * multiRowCount);
  }
  return batchSize;
}

// Detect the byte encoding of a CSV/TSV buffer: BOM first, then a conservative
// alternating-null heuristic for BOM-less UTF-16 (common in Windows tool exports, e.g.
// PowerShell Out-File/Export-Csv). Returns "utf-8" | "utf-16le" | "utf-16be". UTF-8 is
// the safe default — the heuristic only fires on a strong UTF-16 signal, so a plain
// UTF-8/ASCII file (which has no null bytes) is never misdetected.
function detectEncoding(buf) {
  if (!buf || buf.length < 2) return "utf-8";
  if (buf[0] === 0xFF && buf[1] === 0xFE) return "utf-16le";
  if (buf[0] === 0xFE && buf[1] === 0xFF) return "utf-16be";
  const sample = Math.min(buf.length, 4096);
  let evenNull = 0, oddNull = 0, pairs = 0;
  for (let i = 0; i + 1 < sample; i += 2) {
    pairs++;
    if (buf[i] === 0) evenNull++;
    if (buf[i + 1] === 0) oddNull++;
  }
  if (pairs >= 8) {
    if (oddNull / pairs > 0.3 && evenNull / pairs < 0.1) return "utf-16le";
    if (evenNull / pairs > 0.3 && oddNull / pairs < 0.1) return "utf-16be";
  }
  return "utf-8";
}

// ── CSV line parser (RFC 4180 compliant) ───────────────────────────
function parseCSVLine(line, delimiter = ",") {
  const fields = [];
  let inQuotes = false;
  let fieldStart = 0;
  // Fast path: accumulate character ranges instead of per-char string concat
  const parts = []; // array of substrings for the current field (used in quoted fields)
  let useParts = false; // only use parts array when we encounter quotes
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          // Escaped quote — flush range up to here (including first quote), skip second
          parts.push(line.substring(fieldStart, i + 1));
          i++;
          fieldStart = i + 1;
        } else {
          // End of quoted section — flush range before closing quote
          parts.push(line.substring(fieldStart, i));
          fieldStart = i + 1;
          inQuotes = false;
        }
      }
    } else {
      if (ch === '"') {
        // Start quoted section — flush any unquoted prefix
        if (i > fieldStart) parts.push(line.substring(fieldStart, i));
        useParts = true;
        inQuotes = true;
        fieldStart = i + 1;
      } else if (ch === delimiter) {
        if (useParts) {
          if (i > fieldStart) parts.push(line.substring(fieldStart, i));
          fields.push(parts.join(""));
          parts.length = 0;
          useParts = false;
        } else {
          fields.push(line.substring(fieldStart, i));
        }
        fieldStart = i + 1;
      }
    }
  }
  // Final field
  if (useParts) {
    if (line.length > fieldStart) parts.push(line.substring(fieldStart));
    fields.push(parts.join(""));
  } else {
    fields.push(line.substring(fieldStart));
  }
  return fields;
}

// ── Fast CSV field parser (returns array, no allocations beyond the fields array)
// For comma-delimited files that may use quoting.
function parseCSVLineToArray(line, delimiter, colCount) {
  const fields = new Array(colCount);
  let fi = 0;
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
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === delimiter) {
        fields[fi++] = current;
        current = "";
        if (fi >= colCount) return fields;
      } else {
        current += ch;
      }
    }
  }
  if (fi < colCount) fields[fi++] = current;
  // Fill remaining with empty strings
  while (fi < colCount) fields[fi++] = "";
  return fields;
}

function detectDelimiter(firstLine) {
  const tabCount = (firstLine.match(/\t/g) || []).length;
  const commaCount = (firstLine.match(/,/g) || []).length;
  const pipeCount = (firstLine.match(/\|/g) || []).length;
  if (tabCount > commaCount && tabCount > pipeCount) return "\t";
  if (pipeCount > commaCount) return "|";
  return ",";
}

/**
 * Fast split to pre-sized array (avoids String.split() allocating unknown-length array)
 */
function splitToArray(line, delimiter, colCount) {
  const result = new Array(colCount);
  let fi = 0;
  let start = 0;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === delimiter) {
      result[fi++] = line.substring(start, i);
      start = i + 1;
      if (fi >= colCount - 1) break;
    }
  }
  result[fi++] = line.substring(start);
  while (fi < colCount) result[fi++] = "";
  return result;
}

function stripTrailingCR(line) {
  return line.length > 0 && line.charCodeAt(line.length - 1) === 13
    ? line.substring(0, line.length - 1)
    : line;
}

function getWrappedFieldMode(headerName) {
  const h = String(headerName || "").trim().toLowerCase();
  if (!h) return "text";
  if (/^(?:detection_rules|ruletitle|rule_title|description|message)$/i.test(h)) return "text";
  if (/^(?:computer_name|workstation_name|source_ip|target_username|process_name|image|target_object|targetfilename|target_filename|hostname|computer|keypath|hivepath|relativetargetname|event\.eventdata\.(?:image|targetobject|targetfilename))$/i.test(h)) {
    return "join";
  }
  if (/^(?:command_line|commandline|processcommandline|executableinfo|event\.eventdata\.commandline)$/i.test(h)) {
    return "smart";
  }
  return "text";
}

function shouldJoinWrappedField(prevChar, nextChar) {
  if (!prevChar || !nextChar) return true;
  if (/\s/.test(prevChar) || /\s/.test(nextChar)) return false;
  if (/[\\/:._-]/.test(prevChar) || /[\\/:._-]/.test(nextChar)) return true;
  return /[A-Za-z0-9]/.test(prevChar) && /[A-Za-z0-9]/.test(nextChar);
}

function normalizeWrappedFieldValue(value, headerName) {
  const raw = String(value || "");
  if (!/[\r\n]/.test(raw)) return raw;

  const mode = getWrappedFieldMode(headerName);
  if (mode === "text") return raw.replace(/[\r\n]+/g, " ");

  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch !== "\r" && ch !== "\n") {
      out += ch;
      continue;
    }

    let j = i;
    while (j < raw.length && (raw[j] === "\r" || raw[j] === "\n")) j++;
    const prevChar = out.length > 0 ? out[out.length - 1] : "";
    const nextChar = j < raw.length ? raw[j] : "";
    const shouldJoin = mode === "join" || shouldJoinWrappedField(prevChar, nextChar);
    if (!shouldJoin && out.length > 0 && out[out.length - 1] !== " ") out += " ";
    i = j - 1;
  }

  return out;
}

/**
 * Quote-aware CSV record scanner (RFC 4180 compliant).
 * Processes complete records immediately instead of building a giant `records[]`
 * array for the whole chunk, which keeps heap usage bounded on 10GB+ CSV imports.
 */
function scanCSVRecords(str, onRecord) {
  let start = 0;
  let inQuotes = false;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    if (inQuotes) {
      if (ch === 34) { // '"'
        if (i + 1 < str.length && str.charCodeAt(i + 1) === 34) {
          i++; // Skip escaped quote ""
        } else {
          inQuotes = false;
        }
      }
    } else if (ch === 34) {
      inQuotes = true;
    } else if (ch === 10) { // '\n'
      const record = stripTrailingCR(str.substring(start, i));
      if (record.length > 0) onRecord(record);
      start = i + 1;
    }
  }
  return start < str.length ? str.substring(start) : "";
}

/**
 * Count DATA records (header excluded) in CSV text, quote-aware — a record ends only at a newline
 * OUTSIDE quotes, so an embedded-newline field doesn't inflate the count, and blank lines don't
 * count (scanCSVRecords skips length-0 records). Used to detect a parser that ran but emitted an
 * empty / header-only CSV. Returns 0 for empty or header-only input.
 */
function countCsvDataRows(text) {
  if (!text) return 0;
  let recs = 0;
  const tail = scanCSVRecords(String(text), () => { recs++; });
  if (tail) recs++; // final record when the text lacks a trailing newline
  return recs > 1 ? recs - 1 : 0; // minus the header record
}

/**
 * Stream-parse a CSV/TSV file and insert into TimelineDB
 * Uses raw chunk processing instead of readline for maximum throughput.
 *
 * @param {string} filePath - Path to the file
 * @param {string} tabId - Tab identifier
 * @param {TimelineDB} db - Database instance
 * @param {Function} onProgress - Progress callback(rowsImported, fileBytes, totalBytes)
 * @returns {Promise<{headers, rowCount, tsColumns}>}
 */
async function parseCSVStream(filePath, tabId, db, onProgress) {
  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    try { totalBytes = fs.statSync(filePath).size; } catch { /* proceed with 0 */ }
    let bytesRead = 0;
    let lineCount = 0;
    let headers = null;
    // Guard against double resolve/reject — stream end can fire after destroy
    let settled = false;
    const safeReject = (err) => { if (!settled) { settled = true; reject(err); } };
    const safeResolve = (val) => { if (!settled) { settled = true; resolve(val); } };
    let colCount = 0;
    let delimiter = null;
    let batch = new Array(BATCH_SIZE_DEFAULT);
    let batchLen = 0;
    let batchSize = BATCH_SIZE_DEFAULT;
    let lastProgressTime = Date.now();

    // Buffer-level leftover — avoids string concatenation between chunks
    let leftoverBuf = null;

    // Fast-path flag for tab/pipe delimiters (no quoting needed)
    let fastSplit = false;

    // Quote-aware partial record buffer (string) — for comma-delimited RFC 4180 multiline fields
    let partialRecord = "";
    // Decodes Path A (comma, quote-aware) chunks while buffering any trailing partial
    // multi-byte UTF-8 sequence across chunk boundaries, so a character split across a
    // 4MB/128MB read boundary isn't corrupted to U+FFFD. (Path B carries raw bytes in
    // leftoverBuf and decodes only complete lines, so it is already boundary-safe.)
    const utf8Decoder = new StringDecoder("utf-8");

    // Set for a detected UTF-16 source: transcodes each raw chunk to UTF-8 bytes (via a
    // streaming TextDecoder that buffers partial code units across chunk boundaries) so
    // the byte-oriented logic below — and utf8Decoder — operate on UTF-8 unchanged.
    let textDecoder = null;

    // Helper: process a single parsed record (shared by both paths)
    const processRecord = (line) => {
      // Preserve wrapped structured values (paths, hosts, command lines) while still
      // flattening narrative text fields for display.
      const values = parseCSVLineToArray(line, delimiter, colCount);
      for (let vi = 0; vi < colCount; vi++) {
        const v = values[vi];
        if (v && (v.indexOf("\n") !== -1 || v.indexOf("\r") !== -1)) {
          values[vi] = normalizeWrappedFieldValue(v, headers?.[vi]);
        }
      }
      batch[batchLen++] = values;
      lineCount++;

      if (batchLen >= batchSize) {
        db.insertBatchArrays(tabId, batchLen === batch.length ? batch : batch.slice(0, batchLen));
        batchLen = 0;
        const now = Date.now();
        if (now - lastProgressTime >= 200) {
          lastProgressTime = now;
          if (onProgress) onProgress(lineCount, bytesRead, totalBytes);
        }
      }
    };

    const ensurePartialRecordSafe = () => {
      // Large carry-over records are almost always malformed CSV or binary input.
      if (partialRecord.length > 128 * 1024 * 1024) {
        stream.destroy();
        safeReject(new Error("Quoted field exceeds 128MB — file may be corrupted or contain binary data"));
        return false;
      }
      return true;
    };

    // Early binary detection flag — checked on first chunk only
    let firstChunk = true;

    // Adaptive buffer: 128MB for large files (fewer syscalls), 4MB for small files (less memory)
    const hwm = totalBytes > 500 * 1024 * 1024 ? 128 * 1024 * 1024 : 4 * 1024 * 1024;
    const stream = fs.createReadStream(filePath, { highWaterMark: hwm });

    stream.on("data", (rawChunk) => {
      bytesRead += rawChunk.length;

      // Detect encoding on the first chunk. A UTF-16 source is transcoded to UTF-8 bytes
      // (its interleaved null bytes are expected, not binary), so everything below — the
      // byte-oriented header/fastSplit path and utf8Decoder — is unchanged.
      let chunk = rawChunk;
      if (firstChunk) {
        firstChunk = false;
        const enc = detectEncoding(rawChunk);
        if (enc === "utf-16le" || enc === "utf-16be") {
          textDecoder = new TextDecoder(enc); // strips a leading BOM by default
          chunk = Buffer.from(textDecoder.decode(rawChunk, { stream: true }), "utf-8");
        } else {
          // UTF-8/ASCII: a null byte in the first 8KB means real binary — reject.
          const checkLen = Math.min(rawChunk.length, 8192);
          for (let i = 0; i < checkLen; i++) {
            if (rawChunk[i] === 0) {
              stream.destroy();
              safeReject(new Error("File appears to be binary (null bytes in first 8KB) — not a valid CSV/TSV"));
              return;
            }
          }
        }
      } else if (textDecoder) {
        chunk = Buffer.from(textDecoder.decode(rawChunk, { stream: true }), "utf-8");
      }

      // ── Path A: Quote-aware streaming for comma-delimited (RFC 4180 multiline) ──
      // Used after headers are parsed and delimiter is comma (not tab/pipe).
      // Cannot use binary lastNL optimization here because \n may be inside quoted fields.
      if (headers && !fastSplit) {
        const decoded = utf8Decoder.write(chunk);
        const fullStr = partialRecord ? partialRecord + decoded : decoded;
        partialRecord = scanCSVRecords(fullStr, processRecord);
        if (!ensurePartialRecordSafe()) return;
        return;
      }

      // ── Path B: Binary approach for header detection or fastSplit mode ──
      // Safe for tab/pipe (no RFC 4180 quoting) and for the header line (never multiline).
      const buf = leftoverBuf ? Buffer.concat([leftoverBuf, chunk]) : chunk;
      leftoverBuf = null;

      // Find last newline in buffer — only decode complete lines
      const lastNL = buf.lastIndexOf(10); // 10 = '\n'
      if (lastNL === -1) {
        // No complete line yet — save entire buffer
        leftoverBuf = buf;
        // Safety cap: if no newline found in 256MB, likely binary — abort
        if (leftoverBuf.length > 256 * 1024 * 1024) {
          stream.destroy();
          safeReject(new Error("No line breaks found in 256MB of data — file may be binary or corrupted"));
          return;
        }
        return;
      }

      // Save bytes after last newline as leftover (Buffer view, no copy)
      if (lastNL < buf.length - 1) {
        leftoverBuf = buf.subarray(lastNL + 1);
      }

      // Decode only the complete-lines portion
      const str = buf.toString("utf-8", 0, lastNL);
      let lineStart = 0;

      for (let i = 0; i <= str.length; i++) {
        if (i < str.length && str.charCodeAt(i) !== 10) continue;
        let line = stripTrailingCR(str.substring(lineStart, i));
        const nextStart = i + 1;
        lineStart = nextStart;
        if (line.length === 0) continue;

        if (!headers) {
          // First line = headers — strip UTF-8 BOM if present
          if (line.charCodeAt(0) === 0xFEFF) line = line.slice(1);
          delimiter = detectDelimiter(line);
          // Tab/pipe are "fast" only if the file doesn't use RFC 4180 quoting.
          // Check entire first chunk for double-quote characters — if present,
          // fall back to quote-aware parsing to handle multiline quoted fields.
          const hasQuotes = str.indexOf('"') !== -1;
          fastSplit = (delimiter === "\t" || delimiter === "|") && !hasQuotes;
          const rawFields = fastSplit ? line.split(delimiter) : parseCSVLine(line, delimiter);
          headers = rawFields.map((h) => h.trim());

          // Deduplicate headers
          const seen = new Map();
          headers = headers.map((h) => {
            if (!h) h = "Column";
            if (seen.has(h)) {
              const count = seen.get(h) + 1;
              seen.set(h, count);
              return `${h}_${count}`;
            }
            seen.set(h, 0);
            return h;
          });

          colCount = headers.length;
          // Adaptive batch size (byte-target / est. row size, rounded to the DB INSERT chunk).
          // >5GB files get a larger target to amortise transaction-commit count — see helper.
          batchSize = computeImportBatchSize(colCount, totalBytes);
          batch = new Array(batchSize); // re-allocate to actual batch size
          db.createTab(tabId, headers);

          // For comma-delimited: transition remaining data to quote-aware mode
          if (!fastSplit) {
            // Remaining text after the header line is complete, but it may contain
            // quoted multiline records, so switch to the quote-aware scanner now.
            let remainingStr = nextStart < str.length ? str.substring(nextStart) : "";
            if (leftoverBuf) {
              // Feed leftover bytes through the same decoder so a partial multi-byte char
              // at this Path B→A handoff is carried into the first Path A chunk, not mangled.
              const leftoverStr = utf8Decoder.write(leftoverBuf);
              remainingStr = remainingStr ? `${remainingStr}\n${leftoverStr}` : leftoverStr;
              leftoverBuf = null;
            }
            if (remainingStr.length > 0) {
              partialRecord = scanCSVRecords(remainingStr, processRecord);
              if (!ensurePartialRecordSafe()) return;
            }
            return;
          }
          continue;
        }

        // fastSplit data row processing (tab/pipe — no quoting)
        const values = splitToArray(line, delimiter, colCount);
        batch[batchLen++] = values;
        lineCount++;

        if (batchLen >= batchSize) {
          db.insertBatchArrays(tabId, batchLen === batch.length ? batch : batch.slice(0, batchLen));
          batchLen = 0;
          const now = Date.now();
          if (now - lastProgressTime >= 200) {
            lastProgressTime = now;
            if (onProgress) onProgress(lineCount, bytesRead, totalBytes);
          }
        }
      }
    });

    stream.on("end", () => {
      // Flush any trailing buffered partial multi-byte sequence from Path A's decoder
      // onto the final record (no-op in Path B/fastSplit, where the decoder is unused).
      partialRecord += utf8Decoder.end();
      // Process remaining partial record (comma-delimited quote-aware mode)
      if (partialRecord.length > 0 && headers) {
        let line = stripTrailingCR(partialRecord);
        if (line.length > 0) {
          if (fastSplit) {
            const values = splitToArray(line, delimiter, colCount);
            batch[batchLen++] = values;
            lineCount++;
          } else {
            processRecord(line);
          }
        }
        partialRecord = "";
      }

      // Process any leftover partial line (fastSplit mode — last line without trailing newline)
      if (leftoverBuf && leftoverBuf.length > 0 && headers) {
        let line = stripTrailingCR(leftoverBuf.toString("utf-8"));
        if (line.length > 0) {
          const values = fastSplit
            ? splitToArray(line, delimiter, colCount)
            : parseCSVLineToArray(line, delimiter, colCount);
          batch[batchLen++] = values;
          lineCount++;
        }
      }

      // Empty file or no parseable headers — reject cleanly
      if (!headers) {
        safeReject(new Error("No data found — file is empty or contains no parseable headers"));
        return;
      }

      // Insert remaining batch
      if (batchLen > 0) {
        db.insertBatchArrays(tabId, batch.slice(0, batchLen));
      }

      // Finalize
      if (onProgress) onProgress(lineCount, totalBytes, totalBytes);
      const result = db.finalizeImport(tabId);

      safeResolve({
        headers,
        rowCount: result.rowCount,
        tsColumns: result.tsColumns,
        numericColumns: result.numericColumns,
        dayFirstColumns: result.dayFirstColumns || [],
      });
    });

    stream.on("error", safeReject);
  });
}

module.exports = {
  parseCSVLine,
  parseCSVStream,
  scanCSVRecords,
  countCsvDataRows,
  stripTrailingCR,
  detectDelimiter,
  detectEncoding,
  BATCH_SIZE_DEFAULT,
  BATCH_SIZE_MAX_BYTES,
  BATCH_SIZE_MAX_BYTES_LARGE,
  BATCH_SIZE_ROW_CEIL_LARGE,
  LARGE_FILE_THRESHOLD_BYTES,
  computeImportBatchSize,
};
