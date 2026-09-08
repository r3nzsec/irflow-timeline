/**
 * parsers/vhdx.js — read-only reader for VHDX (Hyper-V virtual hard disk, format v2).
 *
 * KAPE's `--vhdx` output (and Windows' own Disk Management exports) are dynamic VHDX
 * containers: a fixed 1 MB header region, a metadata region describing the virtual disk,
 * and a Block Allocation Table (BAT) that maps each fixed-size payload block of the
 * virtual disk to an offset in the file — or marks it absent/zero. This module turns that
 * into one thing the NTFS reader needs: `readAt(virtualOffset, length)`.
 *
 * Scope, deliberately:
 *   • dynamic and fixed VHDX (state ZERO / NOT_PRESENT / UNMAPPED blocks read as zeros)
 *   • differencing disks (HasParent / parent locator) are refused — they need the parent
 *     chain, which a triage package never ships
 *   • the log region IS replayed, in memory only, when the header says it is live (a
 *     non-zero LogGuid). KAPE's DiscUtils writer leaves the log un-flushed on some
 *     builds, and the last BAT/metadata updates live only there. The file on disk is
 *     never modified; log sectors are overlaid on reads.
 *
 * Spec: [MS-VHDX]. All multi-byte integers are little-endian. GUIDs are mixed-endian on
 * disk (Data1..3 little-endian, Data4 big-endian); `readGuid` renders the canonical form.
 */

const fs = require("fs");
const path = require("path");

const MB = 1048576;
const FILE_TYPE_IDENTIFIER = "vhdxfile";
const HEADER_SIGNATURE = "head";
const REGION_SIGNATURE = "regi";
const METADATA_SIGNATURE = "metadata";

const HEADER_OFFSETS = [64 * 1024, 128 * 1024];
const REGION_TABLE_OFFSETS = [192 * 1024, 256 * 1024];
const HEADER_SIZE = 4096;
const REGION_TABLE_SIZE = 64 * 1024;

const GUID_BAT = "2dc27766-f623-4200-9d64-115e9bfd4a08";
const GUID_METADATA = "8b7ca206-4790-4b9a-b8fe-575f050f886e";
const GUID_FILE_PARAMETERS = "caa16737-fa36-4d43-b3b6-33f0aa44e76b";
const GUID_VIRTUAL_DISK_SIZE = "2fa54224-cd1b-4876-b211-5dbed83bf4b8";
const GUID_LOGICAL_SECTOR_SIZE = "8141bf1d-a96f-4709-ba47-f233a8faab5f";
const GUID_PHYSICAL_SECTOR_SIZE = "cda348c7-445d-4471-9cc9-e9885251c556";
const GUID_PARENT_LOCATOR = "a8d35f2d-b30b-454d-abf7-d3d84834ab0c";
const GUID_PAGE83 = "beca12ab-b2e6-4523-93ef-c309e000c746";
const GUID_ZERO = "00000000-0000-0000-0000-000000000000";

// BAT entry states (low 3 bits). Payload blocks:
const PAYLOAD_BLOCK_NOT_PRESENT = 0;
const PAYLOAD_BLOCK_UNDEFINED = 1;
const PAYLOAD_BLOCK_ZERO = 2;
const PAYLOAD_BLOCK_UNMAPPED = 3;
const PAYLOAD_BLOCK_FULLY_PRESENT = 6;
const PAYLOAD_BLOCK_PARTIALLY_PRESENT = 7;

// ── CRC-32C (Castagnoli) — the VHDX header/region-table checksum ───────────────────────
const CRC32C_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0x82F63B78 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();

/** CRC-32C over `buf`, optionally treating `zeroFrom..zeroFrom+4` as zero (the checksum field). */
function crc32c(buf, zeroFrom = -1) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    const b = (zeroFrom >= 0 && i >= zeroFrom && i < zeroFrom + 4) ? 0 : buf[i];
    crc = CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

/** Render an on-disk (mixed-endian) GUID as canonical lower-case text. */
function readGuid(buf, off) {
  const hex = (n) => n.toString(16).padStart(8, "0");
  return [
    hex(buf.readUInt32LE(off)),
    buf.readUInt16LE(off + 4).toString(16).padStart(4, "0"),
    buf.readUInt16LE(off + 6).toString(16).padStart(4, "0"),
    buf.toString("hex", off + 8, off + 10),
    buf.toString("hex", off + 10, off + 16),
  ].join("-");
}

/** Cheap probe: is this a VHDX file at all? (first 8 bytes) */
function isVhdxFile(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const b = Buffer.alloc(8);
    const n = fs.readSync(fd, b, 0, 8, 0);
    return n === 8 && b.toString("latin1") === FILE_TYPE_IDENTIFIER;
  } catch {
    return false;
  } finally {
    if (fd != null) { try { fs.closeSync(fd); } catch { /* ignore */ } }
  }
}

function vhdxError(msg, code = "VHDX_INVALID") {
  return Object.assign(new Error(msg), { code });
}

/**
 * Open a VHDX for reading. Returns a disk object:
 *   { virtualSize, blockSize, logicalSectorSize, physicalSectorSize, isFixed, hasParent,
 *     warnings: string[], readAt(offset, length, out?, outOffset?) → Buffer, close() }
 */
function openVhdx(filePath) {
  const fd = fs.openSync(filePath, "r");
  try {
    return _open(fd, filePath);
  } catch (e) {
    try { fs.closeSync(fd); } catch { /* ignore */ }
    throw e;
  }
}

function _readExact(fd, offset, length) {
  const buf = Buffer.alloc(length);
  let done = 0;
  while (done < length) {
    const n = fs.readSync(fd, buf, done, length - done, offset + done);
    if (n <= 0) break;
    done += n;
  }
  return { buf, bytesRead: done };
}

function _open(fd, filePath) {
  const warnings = [];
  const fileSize = fs.fstatSync(fd).size;

  // ── File type identifier ─────────────────────────────────────────────────────
  const ident = _readExact(fd, 0, 8);
  if (ident.bytesRead < 8 || ident.buf.toString("latin1") !== FILE_TYPE_IDENTIFIER) {
    throw vhdxError(`Not a VHDX file (missing "vhdxfile" signature): ${path.basename(filePath)}`, "VHDX_NOT_VHDX");
  }
  let creator = "";
  try {
    const c = _readExact(fd, 8, 512).buf.toString("utf16le");
    creator = c.replace(/\0.*$/s, "").trim();
  } catch { /* cosmetic */ }

  // ── Headers: two copies, take the valid one with the higher sequence number ──
  let header = null;
  for (const off of HEADER_OFFSETS) {
    const { buf, bytesRead } = _readExact(fd, off, HEADER_SIZE);
    if (bytesRead < HEADER_SIZE) continue;
    if (buf.toString("latin1", 0, 4) !== HEADER_SIGNATURE) continue;
    if (buf.readUInt32LE(4) !== crc32c(buf, 4)) continue;
    const h = {
      sequence: buf.readBigUInt64LE(8),
      fileWriteGuid: readGuid(buf, 16),
      dataWriteGuid: readGuid(buf, 32),
      logGuid: readGuid(buf, 48),
      logVersion: buf.readUInt16LE(64),
      version: buf.readUInt16LE(66),
      logLength: buf.readUInt32LE(68),
      logOffset: Number(buf.readBigUInt64LE(72)),
    };
    if (!header || h.sequence > header.sequence) header = h;
  }
  if (!header) throw vhdxError("VHDX header is corrupt in both copies (bad signature or checksum).");
  if (header.version !== 1) throw vhdxError(`Unsupported VHDX header version ${header.version} (expected 1).`);
  // ── Log replay (read-only overlay) ───────────────────────────────────────────
  // Everything below reads the file through `fileRead`, which patches in log sectors,
  // so the region table, metadata and BAT all see the post-replay state.
  const overlay = header.logGuid !== GUID_ZERO ? _replayLog(fd, fileSize, header, warnings) : [];
  const fileRead = overlay.length ? _overlayReader(fd, overlay) : _plainReader(fd);

  // ── Region table: two copies, first valid wins ───────────────────────────────
  let regions = null;
  for (const off of REGION_TABLE_OFFSETS) {
    const { buf, bytesRead } = fileRead(off, REGION_TABLE_SIZE);
    if (bytesRead < REGION_TABLE_SIZE) continue;
    if (buf.toString("latin1", 0, 4) !== REGION_SIGNATURE) continue;
    if (buf.readUInt32LE(4) !== crc32c(buf, 4)) continue;
    const entryCount = buf.readUInt32LE(8);
    if (entryCount > 2047) continue;
    const list = [];
    for (let i = 0; i < entryCount; i++) {
      const e = 16 + i * 32;
      list.push({
        guid: readGuid(buf, e),
        fileOffset: Number(buf.readBigUInt64LE(e + 16)),
        length: buf.readUInt32LE(e + 24),
        required: (buf.readUInt32LE(e + 28) & 1) === 1,
      });
    }
    regions = list;
    break;
  }
  if (!regions) throw vhdxError("VHDX region table is corrupt in both copies.");

  let batRegion = null, metadataRegion = null;
  for (const r of regions) {
    if (r.guid === GUID_BAT) batRegion = r;
    else if (r.guid === GUID_METADATA) metadataRegion = r;
    else if (r.required) throw vhdxError(`VHDX declares a required region this reader does not understand (${r.guid}).`);
  }
  if (!batRegion || !metadataRegion) throw vhdxError("VHDX is missing its BAT or metadata region.");
  if (metadataRegion.fileOffset + metadataRegion.length > fileSize) throw vhdxError("VHDX metadata region lies beyond the end of the file (truncated image).");

  // ── Metadata region ──────────────────────────────────────────────────────────
  const metaHead = fileRead(metadataRegion.fileOffset, 64 * 1024).buf;
  if (metaHead.toString("latin1", 0, 8) !== METADATA_SIGNATURE) throw vhdxError("VHDX metadata table signature is invalid.");
  const metaCount = metaHead.readUInt16LE(10);
  if (metaCount > 2047) throw vhdxError("VHDX metadata table has an implausible entry count.");
  const items = new Map();
  for (let i = 0; i < metaCount; i++) {
    const e = 32 + i * 32;
    if (e + 32 > metaHead.length) break;
    const guid = readGuid(metaHead, e);
    const offset = metaHead.readUInt32LE(e + 16);
    const length = metaHead.readUInt32LE(e + 20);
    const flags = metaHead.readUInt32LE(e + 24);
    const required = (flags & 4) === 4;
    if (offset + length > metadataRegion.length) throw vhdxError("VHDX metadata item lies outside the metadata region.");
    const known = [GUID_FILE_PARAMETERS, GUID_VIRTUAL_DISK_SIZE, GUID_LOGICAL_SECTOR_SIZE, GUID_PHYSICAL_SECTOR_SIZE, GUID_PARENT_LOCATOR, GUID_PAGE83].includes(guid);
    if (!known && required) throw vhdxError(`VHDX declares a required metadata item this reader does not understand (${guid}).`);
    items.set(guid, fileRead(metadataRegion.fileOffset + offset, length).buf);
  }

  const fileParams = items.get(GUID_FILE_PARAMETERS);
  const diskSize = items.get(GUID_VIRTUAL_DISK_SIZE);
  const lssItem = items.get(GUID_LOGICAL_SECTOR_SIZE);
  if (!fileParams || fileParams.length < 8) throw vhdxError("VHDX metadata is missing File Parameters.");
  if (!diskSize || diskSize.length < 8) throw vhdxError("VHDX metadata is missing Virtual Disk Size.");
  if (!lssItem || lssItem.length < 4) throw vhdxError("VHDX metadata is missing Logical Sector Size.");

  const blockSize = fileParams.readUInt32LE(0);
  const paramFlags = fileParams.readUInt32LE(4);
  const leaveBlocksAllocated = (paramFlags & 1) === 1; // "fixed" VHDX
  const hasParent = (paramFlags & 2) === 2;
  const virtualSize = Number(diskSize.readBigUInt64LE(0));
  const logicalSectorSize = lssItem.readUInt32LE(0);
  const physicalSectorSize = items.get(GUID_PHYSICAL_SECTOR_SIZE)?.readUInt32LE(0) || 4096;

  if (hasParent || items.has(GUID_PARENT_LOCATOR)) {
    throw vhdxError("This is a differencing VHDX (it depends on a parent disk). Merge or export it as a full disk first.", "VHDX_DIFFERENCING");
  }
  if (!Number.isInteger(blockSize) || blockSize < MB || blockSize > 256 * MB || (blockSize & (blockSize - 1)) !== 0) {
    throw vhdxError(`VHDX block size ${blockSize} is invalid (must be a power of two between 1 MB and 256 MB).`);
  }
  if (logicalSectorSize !== 512 && logicalSectorSize !== 4096) throw vhdxError(`VHDX logical sector size ${logicalSectorSize} is invalid.`);
  if (!Number.isSafeInteger(virtualSize) || virtualSize <= 0 || virtualSize % logicalSectorSize !== 0) throw vhdxError("VHDX virtual disk size is invalid.");

  // ── BAT ──────────────────────────────────────────────────────────────────────
  // Payload entries are interleaved with one sector-bitmap entry after every
  // `chunkRatio` payload blocks (the bitmap is only meaningful for differencing disks,
  // but the slot is always there), so payload block i lives at BAT index
  // i + floor(i / chunkRatio).
  const chunkRatio = Math.floor((2 ** 23 * logicalSectorSize) / blockSize);
  const dataBlocks = Math.ceil(virtualSize / blockSize);
  const totalEntries = dataBlocks + Math.floor((dataBlocks - 1) / chunkRatio);
  const batBytes = totalEntries * 8;
  if (batRegion.length < batBytes) throw vhdxError("VHDX BAT region is smaller than the virtual disk requires.");
  if (batRegion.fileOffset + batBytes > fileSize) throw vhdxError("VHDX BAT lies beyond the end of the file (truncated image).");
  const bat = fileRead(batRegion.fileOffset, batBytes).buf;

  let shortReads = 0;
  const zeroFill = (out, from, n) => { out.fill(0, from, from + n); };

  /**
   * Read `length` bytes of the virtual disk starting at `offset` into `out` (allocated if
   * omitted). Absent / zero / unmapped blocks read as zeros. Never returns a short buffer.
   */
  function readAt(offset, length, out = null, outOffset = 0) {
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 0) {
      throw vhdxError("Invalid virtual disk read range.", "VHDX_RANGE");
    }
    if (offset + length > virtualSize) {
      throw vhdxError(`Read past the end of the virtual disk (offset ${offset}, length ${length}, size ${virtualSize}).`, "VHDX_RANGE");
    }
    const buf = out || Buffer.alloc(length);
    let done = 0;
    while (done < length) {
      const vOff = offset + done;
      const blockIndex = Math.floor(vOff / blockSize);
      const inBlock = vOff - blockIndex * blockSize;
      const n = Math.min(length - done, blockSize - inBlock);
      const batIndex = blockIndex + Math.floor(blockIndex / chunkRatio);
      const entry = bat.readBigUInt64LE(batIndex * 8);
      const state = Number(entry & 7n);
      const fileOffset = Number(entry >> 20n) * MB;
      const dst = outOffset + done;
      if (state === PAYLOAD_BLOCK_FULLY_PRESENT) {
        if (fileOffset === 0) throw vhdxError("VHDX BAT marks a block present at file offset 0 (corrupt BAT).");
        const got = fileRead(fileOffset + inBlock, n, buf, dst).bytesRead;
        if (got < n) { shortReads++; zeroFill(buf, dst + got, n - got); }
      } else if (state === PAYLOAD_BLOCK_PARTIALLY_PRESENT) {
        throw vhdxError("VHDX contains partially-present blocks, which only occur in differencing disks.", "VHDX_DIFFERENCING");
      } else if (state === PAYLOAD_BLOCK_NOT_PRESENT || state === PAYLOAD_BLOCK_UNDEFINED
        || state === PAYLOAD_BLOCK_ZERO || state === PAYLOAD_BLOCK_UNMAPPED) {
        zeroFill(buf, dst, n);
      } else {
        throw vhdxError(`VHDX BAT entry has an invalid state ${state}.`);
      }
      done += n;
    }
    return buf;
  }

  let allocatedBlocks = 0;
  for (let i = 0; i < dataBlocks; i++) {
    const entry = bat.readBigUInt64LE((i + Math.floor(i / chunkRatio)) * 8);
    if (Number(entry & 7n) === PAYLOAD_BLOCK_FULLY_PRESENT) allocatedBlocks++;
  }

  return {
    filePath,
    fileSize,
    creator,
    virtualSize,
    blockSize,
    logicalSectorSize,
    physicalSectorSize,
    isFixed: leaveBlocksAllocated,
    hasParent,
    dataBlocks,
    allocatedBlocks,
    allocatedBytes: allocatedBlocks * blockSize,
    warnings,
    readAt,
    /** Number of block reads that came up short (file truncated under the BAT). */
    get shortReads() { return shortReads; },
    close() { try { fs.closeSync(fd); } catch { /* ignore */ } },
  };
}

/** Plain file reader: (offset, length, out?, outOffset?) → { buf, bytesRead }. */
function _plainReader(fd) {
  return (offset, length, out = null, outOffset = 0) => {
    const buf = out || Buffer.alloc(length);
    let done = 0;
    while (done < length) {
      const n = fs.readSync(fd, buf, outOffset + done, length - done, offset + done);
      if (n <= 0) break;
      done += n;
    }
    return { buf, bytesRead: done };
  };
}

/**
 * File reader that patches replayed log sectors over the raw file. `overlay` is a list of
 * { offset, length, data|null } (null = zeroes), later entries winning over earlier ones.
 */
function _overlayReader(fd, overlay) {
  const plain = _plainReader(fd);
  return (offset, length, out = null, outOffset = 0) => {
    const res = plain(offset, length, out, outOffset);
    const buf = res.buf;
    let bytesRead = res.bytesRead;
    const end = offset + length;
    for (const o of overlay) {
      const oEnd = o.offset + o.length;
      if (oEnd <= offset || o.offset >= end) continue;
      const from = Math.max(offset, o.offset);
      const to = Math.min(end, oEnd);
      const dst = outOffset + (from - offset);
      if (o.data) o.data.copy(buf, dst, from - o.offset, to - o.offset);
      else buf.fill(0, dst, dst + (to - from));
      // A log sector may legitimately extend the file (LastFileOffset); count it as read.
      bytesRead = Math.max(bytesRead, to - offset);
    }
    return { buf, bytesRead };
  };
}

const LOG_SECTOR = 4096;

/**
 * Parse the log region and return the overlay produced by replaying the active sequence
 * ([MS-VHDX] 2.3.3): the valid entry with the highest sequence number is the head, its
 * Tail field points at the first entry of the sequence, and entries are applied in order
 * from tail to head. Anything malformed ends the replay with a warning rather than an
 * error — a partially-replayed image is still far better than refusing the file.
 */
function _replayLog(fd, fileSize, header, warnings) {
  const overlay = [];
  const { logOffset, logLength, logGuid } = header;
  if (!logLength || logOffset + logLength > fileSize) {
    warnings.push("The VHDX header points at a log region beyond the end of the file; the log was not replayed.");
    return overlay;
  }
  const log = _readExact(fd, logOffset, logLength).buf;

  // Every entry starts on a 4 KB boundary. Collect the valid ones (signature, GUID,
  // checksum over the whole entry, sane length) keyed by their offset in the region.
  const entries = new Map();
  for (let off = 0; off + 64 <= log.length; off += LOG_SECTOR) {
    if (log.toString("latin1", off, off + 4) !== "loge") continue;
    if (readGuid(log, off + 32) !== logGuid) continue;
    const entryLength = log.readUInt32LE(off + 8);
    if (entryLength < 64 || entryLength % LOG_SECTOR !== 0 || off + entryLength > log.length) continue;
    const entry = log.subarray(off, off + entryLength);
    if (entry.readUInt32LE(4) !== crc32c(entry, 4)) continue;
    entries.set(off, {
      offset: off,
      length: entryLength,
      tail: log.readUInt32LE(off + 12),
      sequence: log.readBigUInt64LE(off + 16),
      descriptorCount: log.readUInt32LE(off + 24),
    });
  }
  if (entries.size === 0) {
    warnings.push("The VHDX header marks its log as live but no valid log entries were found; the image is read as-is.");
    return overlay;
  }

  let head = null;
  for (const e of entries.values()) if (!head || e.sequence > head.sequence) head = e;

  // Walk from the tail forward (circularly) until we reach the head.
  const ordered = [];
  let cur = entries.get(head.tail);
  let expected = cur?.sequence;
  let guard = 0;
  while (cur && guard++ < 1_000_000) {
    if (cur.sequence !== expected) break;
    ordered.push(cur);
    if (cur.offset === head.offset) break;
    const next = (cur.offset + cur.length) % log.length;
    cur = entries.get(next);
    expected = expected + 1n;
  }
  if (!ordered.length || ordered[ordered.length - 1].offset !== head.offset) {
    // The tail chain is broken; fall back to applying every entry in sequence order.
    ordered.length = 0;
    for (const e of [...entries.values()].sort((a, b) => (a.sequence < b.sequence ? -1 : 1))) ordered.push(e);
    warnings.push("The VHDX log chain is inconsistent; entries were replayed in sequence order.");
  }

  let applied = 0;
  for (const e of ordered) {
    const descBytes = 64 + e.descriptorCount * 32;
    const dataStart = Math.ceil(descBytes / LOG_SECTOR) * LOG_SECTOR;
    if (dataStart > e.length) continue;
    let dataIndex = 0;
    for (let i = 0; i < e.descriptorCount; i++) {
      const d = e.offset + 64 + i * 32;
      if (d + 32 > log.length) break;
      const sig = log.toString("latin1", d, d + 4);
      const fileOffset = Number(log.readBigUInt64LE(d + 16));
      if (sig === "zero") {
        const zeroLength = Number(log.readBigUInt64LE(d + 8));
        if (zeroLength > 0 && Number.isSafeInteger(fileOffset)) overlay.push({ offset: fileOffset, length: zeroLength, data: null });
        applied++;
      } else if (sig === "desc") {
        const s = e.offset + dataStart + dataIndex * LOG_SECTOR;
        dataIndex++;
        if (s + LOG_SECTOR > e.offset + e.length) break;
        if (log.toString("latin1", s, s + 4) !== "data") continue;
        // Reconstruct the 4 KB sector: LeadingBytes(8) + Data(4084) + TrailingBytes(4).
        const sector = Buffer.alloc(LOG_SECTOR);
        log.copy(sector, 0, d + 8, d + 16);            // LeadingBytes (u64, raw bytes)
        log.copy(sector, 8, s + 8, s + 8 + 4084);      // Data
        log.copy(sector, 4092, d + 4, d + 8);          // TrailingBytes (u32, raw bytes)
        overlay.push({ offset: fileOffset, length: LOG_SECTOR, data: sector });
        applied++;
      } else {
        break;
      }
    }
  }
  if (applied) warnings.push(`The VHDX was not cleanly detached; ${applied} logged write${applied === 1 ? " was" : "s were"} replayed in memory (the file on disk is unchanged).`);
  return overlay;
}

module.exports = {
  openVhdx,
  isVhdxFile,
  crc32c,
  readGuid,
  MB,
  GUIDS: {
    BAT: GUID_BAT,
    METADATA: GUID_METADATA,
    FILE_PARAMETERS: GUID_FILE_PARAMETERS,
    VIRTUAL_DISK_SIZE: GUID_VIRTUAL_DISK_SIZE,
    LOGICAL_SECTOR_SIZE: GUID_LOGICAL_SECTOR_SIZE,
    PHYSICAL_SECTOR_SIZE: GUID_PHYSICAL_SECTOR_SIZE,
    PARENT_LOCATOR: GUID_PARENT_LOCATOR,
    PAGE83: GUID_PAGE83,
  },
  BAT_STATES: {
    NOT_PRESENT: PAYLOAD_BLOCK_NOT_PRESENT,
    UNDEFINED: PAYLOAD_BLOCK_UNDEFINED,
    ZERO: PAYLOAD_BLOCK_ZERO,
    UNMAPPED: PAYLOAD_BLOCK_UNMAPPED,
    FULLY_PRESENT: PAYLOAD_BLOCK_FULLY_PRESENT,
    PARTIALLY_PRESENT: PAYLOAD_BLOCK_PARTIALLY_PRESENT,
  },
};
