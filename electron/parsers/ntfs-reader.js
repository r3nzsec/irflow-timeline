/**
 * parsers/ntfs-reader.js — read-only NTFS volume reader over a random-access disk.
 *
 * Enough NTFS to enumerate every live file with its full path and copy its primary data
 * stream out: boot sector → $MFT data runs → per-record $FILE_NAME / $DATA (resident and
 * non-resident, including $ATTRIBUTE_LIST-split runs), fixup arrays, sparse runs. It is
 * the layer under "open a VHDX as a triage collection": the container reader hands us
 * `readAt`, we hand the extractor a file list and `readFile`.
 *
 * Not attempted, and reported instead of guessed at:
 *   • NTFS-compressed (LZNT1 / WOF) and EFS-encrypted streams — flagged on the entry
 *   • deleted records — skipped (this is a collection reader, not a carver; the existing
 *     $MFT parser is the tool for deleted-file analysis)
 *   • alternate data streams — not enumerated
 *
 * `disk` is anything with `{ readAt(offset, length, out?, outOffset?) → Buffer,
 * virtualSize, logicalSectorSize? }` (see parsers/vhdx.js).
 */

const ATTR_STANDARD_INFORMATION = 0x10;
const ATTR_ATTRIBUTE_LIST = 0x20;
const ATTR_FILE_NAME = 0x30;
const ATTR_DATA = 0x80;
const ATTR_END = 0xFFFFFFFF;

const ATTR_FLAG_COMPRESSED = 0x0001;
const ATTR_FLAG_ENCRYPTED = 0x4000;
const ATTR_FLAG_SPARSE = 0x8000;

const RECORD_IN_USE = 0x0001;
const RECORD_IS_DIRECTORY = 0x0002;

const ROOT_ENTRY = 5;
const FIRST_USER_ENTRY = 16; // 0–15 are reserved metafile records
const ENTRY_MASK = 0xFFFFFFFFFFFFn;

// NTFS partition type / GPT type GUID for a Microsoft basic data partition. We probe the
// boot sector regardless — the type is a hint, the OEM ID is the proof.
const MBR_TYPE_GPT_PROTECTIVE = 0xEE;
const GPT_TYPE_EMPTY = "00000000-0000-0000-0000-000000000000";

function ntfsError(msg, code = "NTFS_INVALID") {
  return Object.assign(new Error(msg), { code });
}

// ── Partition discovery ─────────────────────────────────────────────────────────────────

function _isNtfsBootSector(buf) {
  // No 0x55AA check: DiscUtils (KAPE's VHDX writer) emits a boot sector without the boot
  // signature or jump instruction. The OEM ID plus a sane BPB is the proof.
  if (buf.length < 512 || buf.toString("latin1", 3, 11) !== "NTFS    ") return false;
  const bps = buf.readUInt16LE(11);
  const spc = buf[13];
  return [512, 1024, 2048, 4096].includes(bps) && spc > 0 && buf.readUInt16LE(14) === 0;
}

function _guidAt(buf, off) {
  const { readGuid } = require("./vhdx");
  return readGuid(buf, off);
}

/**
 * Find NTFS volumes on a disk: a bare volume (boot sector at 0), an MBR partition table,
 * or a GPT (behind a protective MBR). Returns [{ offset, size, index, scheme }].
 */
function findNtfsVolumes(disk) {
  const sectorSize = disk.logicalSectorSize || 512;
  const out = [];
  if (disk.virtualSize < 512) return out;
  const s0 = disk.readAt(0, Math.min(sectorSize, disk.virtualSize));
  if (_isNtfsBootSector(s0)) {
    out.push({ offset: 0, size: disk.virtualSize, index: 0, scheme: "raw" });
    return out;
  }
  if (s0.readUInt16LE(510) !== 0xAA55) return out;

  const mbr = [];
  for (let i = 0; i < 4; i++) {
    const e = 446 + i * 16;
    mbr.push({ type: s0[e + 4], lba: s0.readUInt32LE(e + 8), sectors: s0.readUInt32LE(e + 12) });
  }

  const probe = (offset, size, index, scheme) => {
    if (offset < 0 || offset + 512 > disk.virtualSize) return;
    let bs;
    try { bs = disk.readAt(offset, 512); } catch { return; }
    if (_isNtfsBootSector(bs)) out.push({ offset, size, index, scheme });
  };

  if (mbr.some((p) => p.type === MBR_TYPE_GPT_PROTECTIVE)) {
    // GPT header at LBA 1.
    const hdr = disk.readAt(sectorSize, Math.min(512, disk.virtualSize - sectorSize));
    if (hdr.toString("latin1", 0, 8) === "EFI PART") {
      const entriesLba = Number(hdr.readBigUInt64LE(72));
      const count = Math.min(hdr.readUInt32LE(80), 128);
      const entrySize = hdr.readUInt32LE(84) || 128;
      if (entrySize >= 128 && entrySize <= 4096 && entriesLba > 0) {
        const total = count * entrySize;
        const start = entriesLba * sectorSize;
        if (start + total <= disk.virtualSize) {
          const table = disk.readAt(start, total);
          for (let i = 0; i < count; i++) {
            const e = i * entrySize;
            if (_guidAt(table, e) === GPT_TYPE_EMPTY) continue;
            const first = Number(table.readBigUInt64LE(e + 32));
            const last = Number(table.readBigUInt64LE(e + 40));
            if (last < first) continue;
            probe(first * sectorSize, (last - first + 1) * sectorSize, i, "gpt");
          }
        }
      }
    }
    return out;
  }

  mbr.forEach((p, i) => {
    if (!p.lba || !p.sectors || p.type === 0) return;
    probe(p.lba * sectorSize, p.sectors * sectorSize, i, "mbr");
  });
  return out;
}

// ── Record-level helpers ────────────────────────────────────────────────────────────────

/** Undo the update-sequence fixups in place. Returns false if the record is torn.
 *  NTFS always writes the USA against a 512-byte stride, even on 4Kn volumes. */
const NTFS_FIXUP_STRIDE = 512;
function applyFixup(buf) {
  const usaOffset = buf.readUInt16LE(4);
  const usaCount = buf.readUInt16LE(6);
  if (usaCount <= 1 || usaOffset < 42 || usaOffset + usaCount * 2 > buf.length) return usaCount <= 1;
  if ((usaCount - 1) * NTFS_FIXUP_STRIDE !== buf.length) return false;
  const usn = buf.readUInt16LE(usaOffset);
  for (let i = 1; i < usaCount; i++) {
    const sectorEnd = i * NTFS_FIXUP_STRIDE - 2;
    if (sectorEnd + 2 > buf.length) return false;
    if (buf.readUInt16LE(sectorEnd) !== usn) return false;
    buf.writeUInt16LE(buf.readUInt16LE(usaOffset + i * 2), sectorEnd);
  }
  return true;
}

/**
 * Decode a data-run list starting at `pos`. Returns [{ vcn, lcn, clusters }] with
 * lcn = -1 for sparse runs. `startVcn` is the attribute fragment's lowest VCN.
 */
function parseRunList(buf, pos, startVcn = 0) {
  const runs = [];
  let lcn = 0;
  let vcn = startVcn;
  while (pos < buf.length) {
    const header = buf[pos];
    if (header === 0) break;
    const lenSize = header & 0x0F;
    const offSize = header >> 4;
    if (lenSize === 0 || lenSize > 8 || offSize > 8 || pos + 1 + lenSize + offSize > buf.length) break;
    let clusters = 0;
    for (let i = lenSize - 1; i >= 0; i--) clusters = clusters * 256 + buf[pos + 1 + i];
    let delta = 0;
    if (offSize > 0) {
      for (let i = offSize - 1; i >= 0; i--) delta = delta * 256 + buf[pos + 1 + lenSize + i];
      if (buf[pos + lenSize + offSize] & 0x80) delta -= 2 ** (offSize * 8); // sign-extend
    }
    if (clusters <= 0) break;
    if (offSize === 0) {
      runs.push({ vcn, lcn: -1, clusters });
    } else {
      lcn += delta;
      if (lcn < 0) break;
      runs.push({ vcn, lcn, clusters });
    }
    vcn += clusters;
    pos += 1 + lenSize + offSize;
  }
  return runs;
}

function _parseFileName(buf, pos, attrLen) {
  const contentOff = buf.readUInt16LE(pos + 20);
  const c = pos + contentOff;
  if (c + 66 > buf.length || contentOff + 66 > attrLen) return null;
  const parentRef = buf.readBigUInt64LE(c);
  const nameLen = buf[c + 64];
  const namespace = buf[c + 65];
  if (c + 66 + nameLen * 2 > buf.length) return null;
  return {
    parentEntry: Number(parentRef & ENTRY_MASK),
    parentSeq: Number(parentRef >> 48n),
    name: buf.toString("utf16le", c + 66, c + 66 + nameLen * 2),
    namespace, // 0 POSIX, 1 Win32, 2 DOS, 3 Win32+DOS
    flags: buf.readUInt32LE(c + 56),
  };
}

/** Rank a $FILE_NAME for display: Win32+DOS > Win32 > POSIX > DOS. */
function _fnRank(fn) {
  return fn.namespace === 3 ? 3 : fn.namespace === 1 ? 2 : fn.namespace === 0 ? 1 : 0;
}

/**
 * Parse a single unnamed $DATA attribute fragment at `pos`. Returns a "fragment":
 *   resident: { resident: true, data: Buffer, size }
 *   non-resident: { resident: false, startVcn, endVcn, runs, allocSize, realSize, initSize, flags }
 */
function _parseDataFragment(buf, pos, attrLen) {
  const nonResident = buf[pos + 8];
  const flags = buf.readUInt16LE(pos + 12);
  if (!nonResident) {
    const size = buf.readUInt32LE(pos + 16);
    const off = buf.readUInt16LE(pos + 20);
    if (off + size > attrLen || pos + off + size > buf.length) return null;
    return { resident: true, size, data: Buffer.from(buf.subarray(pos + off, pos + off + size)), flags };
  }
  if (attrLen < 64 || pos + 64 > buf.length) return null;
  const startVcn = Number(buf.readBigUInt64LE(pos + 16));
  const endVcn = Number(buf.readBigUInt64LE(pos + 24));
  const runOff = buf.readUInt16LE(pos + 32);
  const compressionUnit = buf.readUInt16LE(pos + 34);
  const allocSize = Number(buf.readBigUInt64LE(pos + 40));
  const realSize = Number(buf.readBigUInt64LE(pos + 48));
  const initSize = Number(buf.readBigUInt64LE(pos + 56));
  const runs = runOff >= 64 && runOff < attrLen ? parseRunList(buf.subarray(pos, pos + attrLen), runOff, startVcn) : [];
  return { resident: false, startVcn, endVcn, runs, allocSize, realSize, initSize, flags, compressionUnit };
}

function _parseAttributeList(content) {
  const entries = [];
  let pos = 0;
  while (pos + 26 <= content.length) {
    const type = content.readUInt32LE(pos);
    const len = content.readUInt16LE(pos + 4);
    if (len < 26 || pos + len > content.length) break;
    entries.push({
      type,
      nameLen: content[pos + 6],
      startVcn: Number(content.readBigUInt64LE(pos + 8)),
      mftEntry: Number(content.readBigUInt64LE(pos + 16) & ENTRY_MASK),
    });
    pos += len;
  }
  return entries;
}

// ── Volume ──────────────────────────────────────────────────────────────────────────────

class NtfsVolume {
  /**
   * @param {object} disk  — { readAt, virtualSize }
   * @param {number} volumeOffset — byte offset of the boot sector on `disk`
   * @param {number} [volumeSize]
   */
  constructor(disk, volumeOffset = 0, volumeSize = 0) {
    this.disk = disk;
    this.volumeOffset = volumeOffset;
    this.volumeSize = volumeSize || (disk.virtualSize - volumeOffset);
    this._records = new Map(); // entry → parsed record (cache for extension-record lookups)
    this._open();
  }

  _open() {
    const bs = this.disk.readAt(this.volumeOffset, 512);
    if (!_isNtfsBootSector(bs)) throw ntfsError("Not an NTFS boot sector.");
    this.bytesPerSector = bs.readUInt16LE(11);
    const spc = bs[13];
    this.sectorsPerCluster = spc >= 0x80 ? 2 ** (256 - spc) : spc;
    this.clusterSize = this.bytesPerSector * this.sectorsPerCluster;
    this.totalSectors = Number(bs.readBigUInt64LE(40));
    this.mftLcn = Number(bs.readBigUInt64LE(48));
    this.mftMirrorLcn = Number(bs.readBigUInt64LE(56));
    const cpfr = bs.readInt8(64);
    this.recordSize = cpfr < 0 ? 2 ** (-cpfr) : cpfr * this.clusterSize;
    this.serial = bs.readBigUInt64LE(72).toString(16).padStart(16, "0");
    if (![512, 1024, 2048, 4096].includes(this.bytesPerSector)) throw ntfsError(`NTFS bytes-per-sector ${this.bytesPerSector} is invalid.`);
    if (!this.sectorsPerCluster || this.clusterSize > 2 * 1048576) throw ntfsError(`NTFS cluster size ${this.clusterSize} is invalid.`);
    if (this.recordSize < 1024 || this.recordSize > 65536) throw ntfsError(`NTFS record size ${this.recordSize} is invalid.`);
    this.volumeBytes = this.totalSectors * this.bytesPerSector;

    // Bootstrap $MFT from record 0, read directly at the boot sector's MFT LCN.
    const raw = this._readClusters(this.mftLcn, 0, this.recordSize);
    if (raw.toString("latin1", 0, 4) !== "FILE") throw ntfsError("The $MFT record is not a FILE record (corrupt volume?).");
    applyFixup(raw);
    const rec0 = this._parseRecordBuffer(raw, 0);
    // The first $DATA fragment in the base record always covers the records that any
    // $ATTRIBUTE_LIST extensions live in, so we can seed the run map with it and then
    // resolve the rest through the normal path.
    this.mftRuns = rec0.dataFragments.find((f) => !f.resident)?.runs || [];
    if (!this.mftRuns.length) throw ntfsError("The $MFT record has no non-resident $DATA runs.");
    this._records.set(0, rec0);
    const full = this._resolveData(rec0);
    this.mftRuns = full.runs;
    this.mftSize = full.realSize;
    this.recordCount = Math.floor(this.mftSize / this.recordSize);
  }

  _readClusters(lcn, byteOffset, length, out = null, outOffset = 0) {
    const abs = this.volumeOffset + lcn * this.clusterSize + byteOffset;
    return this.disk.readAt(abs, length, out, outOffset);
  }

  /** Read `length` bytes at logical byte offset `off` of a run list (sparse → zeros). */
  _readRuns(runs, off, length, out = null, outOffset = 0) {
    const buf = out || Buffer.alloc(length);
    let done = 0;
    const cs = this.clusterSize;
    for (const run of runs) {
      if (done >= length) break;
      const runStart = run.vcn * cs;
      const runEnd = runStart + run.clusters * cs;
      const want = off + done;
      if (want >= runEnd) continue;
      if (want < runStart) { // hole in the VCN space — treat as zeros
        const n = Math.min(length - done, runStart - want);
        buf.fill(0, outOffset + done, outOffset + done + n);
        done += n;
        if (done >= length) break;
      }
      const inRun = (off + done) - runStart;
      const n = Math.min(length - done, runEnd - (off + done));
      if (n <= 0) continue;
      if (run.lcn < 0) buf.fill(0, outOffset + done, outOffset + done + n);
      else this._readClusters(run.lcn, inRun, n, buf, outOffset + done);
      done += n;
    }
    if (done < length) buf.fill(0, outOffset + done, outOffset + length);
    return buf;
  }

  /** Raw MFT record `n` (fixups applied) or null if it is not a FILE record. */
  readRecordBuffer(n) {
    if (n < 0 || n >= (this.recordCount || Infinity)) return null;
    const buf = this._readRuns(this.mftRuns, n * this.recordSize, this.recordSize);
    if (buf.toString("latin1", 0, 4) !== "FILE") return null;
    applyFixup(buf);
    return buf;
  }

  _parseRecordBuffer(buf, entry) {
    const rec = {
      entry,
      seq: buf.readUInt16LE(16),
      flags: buf.readUInt16LE(22),
      baseEntry: Number(buf.readBigUInt64LE(32) & ENTRY_MASK),
      inUse: false,
      isDir: false,
      fileNames: [],
      dataFragments: [],
      attrList: null,
    };
    rec.inUse = (rec.flags & RECORD_IN_USE) !== 0;
    rec.isDir = (rec.flags & RECORD_IS_DIRECTORY) !== 0;
    let pos = buf.readUInt16LE(20);
    if (pos < 42 || pos >= buf.length) return rec;
    while (pos + 16 <= buf.length) {
      const type = buf.readUInt32LE(pos);
      if (type === ATTR_END || type === 0) break;
      const attrLen = buf.readUInt32LE(pos + 4);
      if (attrLen < 16 || pos + attrLen > buf.length) break;
      const nonResident = buf[pos + 8];
      const nameLen = buf[pos + 9];
      try {
        if (type === ATTR_FILE_NAME && !nonResident) {
          const fn = _parseFileName(buf, pos, attrLen);
          if (fn) rec.fileNames.push(fn);
        } else if (type === ATTR_DATA && nameLen === 0) {
          const frag = _parseDataFragment(buf, pos, attrLen);
          if (frag) rec.dataFragments.push(frag);
        } else if (type === ATTR_ATTRIBUTE_LIST) {
          if (!nonResident) {
            const size = buf.readUInt32LE(pos + 16);
            const off = buf.readUInt16LE(pos + 20);
            if (off + size <= attrLen) rec.attrList = _parseAttributeList(buf.subarray(pos + off, pos + off + size));
          } else {
            const frag = _parseDataFragment(buf, pos, attrLen);
            if (frag && !frag.resident && frag.realSize > 0 && frag.realSize < 16 * 1048576) {
              rec.attrList = _parseAttributeList(this._readRuns(frag.runs, 0, frag.realSize));
            }
          }
        }
      } catch { /* skip a corrupt attribute, keep the record */ }
      pos += attrLen;
    }
    return rec;
  }

  /** Parsed record `n` (cached). */
  getRecord(n) {
    if (this._records.has(n)) return this._records.get(n);
    const buf = this.readRecordBuffer(n);
    const rec = buf ? this._parseRecordBuffer(buf, n) : null;
    this._records.set(n, rec);
    return rec;
  }

  /**
   * Resolve the primary $DATA stream of a base record, following $ATTRIBUTE_LIST into
   * extension records. Returns { resident, data?, runs, realSize, initSize, compressed,
   * encrypted, sparse } or null when the record has no $DATA at all (directories).
   */
  _resolveData(rec) {
    let fragments = rec.dataFragments.slice();
    if (rec.attrList) {
      const seen = new Set([rec.entry]);
      for (const e of rec.attrList) {
        if (e.type !== ATTR_DATA || e.nameLen !== 0 || seen.has(e.mftEntry)) continue;
        seen.add(e.mftEntry);
        const ext = this.getRecord(e.mftEntry);
        if (!ext || ext.baseEntry !== rec.entry) continue;
        fragments = fragments.concat(ext.dataFragments);
      }
    }
    if (!fragments.length) return null;
    const resident = fragments.find((f) => f.resident);
    if (resident && fragments.length === 1) {
      return {
        resident: true, data: resident.data, runs: [], realSize: resident.size, initSize: resident.size,
        compressed: (resident.flags & ATTR_FLAG_COMPRESSED) !== 0, encrypted: (resident.flags & ATTR_FLAG_ENCRYPTED) !== 0, sparse: false,
      };
    }
    const nonRes = fragments.filter((f) => !f.resident).sort((a, b) => a.startVcn - b.startVcn);
    if (!nonRes.length) return null;
    const head = nonRes[0];
    const runs = [];
    for (const f of nonRes) for (const r of f.runs) runs.push(r);
    return {
      resident: false,
      runs,
      realSize: head.realSize,
      initSize: head.initSize,
      allocSize: head.allocSize,
      compressed: (head.flags & ATTR_FLAG_COMPRESSED) !== 0,
      encrypted: (head.flags & ATTR_FLAG_ENCRYPTED) !== 0,
      sparse: (head.flags & ATTR_FLAG_SPARSE) !== 0 || runs.some((r) => r.lcn < 0),
      truncatedRuns: runs.reduce((n, r) => n + r.clusters, 0) * this.clusterSize < (head.initSize || 0),
    };
  }

  /**
   * Enumerate live files and directories. Returns
   *   { files: [{ entry, seq, path, segments, size, isDir, compressed, encrypted, sparse, data }],
   *     orphans, records, skippedRecords }
   * `path` uses backslashes (NTFS-native, and what the artifact classifier expects).
   * `onProgress(recordsDone, recordsTotal)` is called every 4096 records; `isCancelled()`
   * may throw to abort.
   */
  listFiles({ onProgress = null, isCancelled = null, includeReserved = false } = {}) {
    const nodes = new Map(); // entry → { seq, name, parentEntry, parentSeq, isDir, rec }
    const total = this.recordCount;
    for (let n = 0; n < total; n++) {
      if ((n & 4095) === 0) {
        if (isCancelled) isCancelled();
        if (onProgress) onProgress(n, total);
      }
      let rec;
      try { rec = this.getRecord(n); } catch { rec = null; }
      if (n >= FIRST_USER_ENTRY && n !== ROOT_ENTRY && n > 64) this._records.delete(n); // keep the cache bounded
      if (!rec || !rec.inUse) continue;
      if (rec.baseEntry !== 0) continue; // extension record; resolved from its base
      if (!rec.fileNames.length) continue;
      let best = rec.fileNames[0];
      for (const fn of rec.fileNames) if (_fnRank(fn) > _fnRank(best)) best = fn;
      nodes.set(n, { seq: rec.seq, name: best.name, parentEntry: best.parentEntry, parentSeq: best.parentSeq, isDir: rec.isDir, rec });
    }
    if (onProgress) onProgress(total, total);

    // Resolve paths. Root is entry 5 and is its own parent.
    const pathCache = new Map([[ROOT_ENTRY, []]]);
    const resolve = (entry) => {
      if (pathCache.has(entry)) return pathCache.get(entry);
      const chain = [];
      let cur = entry;
      let result = null;
      const visiting = new Set();
      while (true) {
        if (pathCache.has(cur)) { result = pathCache.get(cur); break; }
        if (visiting.has(cur) || chain.length > 512) { result = null; break; }
        visiting.add(cur);
        const node = nodes.get(cur);
        if (!node) { result = null; break; }
        const parent = nodes.get(node.parentEntry);
        if (node.parentEntry !== ROOT_ENTRY && (!parent || !parent.isDir || parent.seq !== node.parentSeq)) { result = null; break; }
        chain.push(cur);
        cur = node.parentEntry;
      }
      // Unwind: chain holds entries from `entry` up to (not including) the cached ancestor.
      for (let i = chain.length - 1; i >= 0; i--) {
        const e = chain[i];
        result = result === null ? null : result.concat(nodes.get(e).name);
        pathCache.set(e, result);
      }
      return pathCache.get(entry) ?? null;
    };

    const files = [];
    let orphans = 0;
    for (const [entry, node] of nodes) {
      if (entry === ROOT_ENTRY) continue;
      if (!includeReserved && entry < FIRST_USER_ENTRY) continue;
      const segments = resolve(entry);
      if (!segments) { orphans++; continue; }
      let data = null;
      if (!node.isDir) {
        try { data = this._resolveData(node.rec); } catch { data = null; }
      }
      files.push({
        entry,
        seq: node.seq,
        segments,
        path: segments.join("\\"),
        isDir: node.isDir,
        size: data ? data.realSize : 0,
        compressed: !!data?.compressed,
        encrypted: !!data?.encrypted,
        sparse: !!data?.sparse,
        data,
      });
      node.rec = null; // release the parsed record; `data` keeps only what extraction needs
    }
    this._records.clear();
    return { files, orphans, records: total };
  }

  /**
   * Stream a file's primary data stream to `sink(chunk)`. Bytes past the initialized size
   * read as zeros (NTFS semantics). Compressed/encrypted streams throw — the caller
   * decides how to report them.
   */
  readFile(file, sink, { chunkSize = 4 * 1048576, isCancelled = null } = {}) {
    const data = file.data;
    if (!data) throw ntfsError("The record has no primary data stream.", "NTFS_NO_DATA");
    if (data.compressed) throw ntfsError("NTFS-compressed stream (not supported).", "NTFS_COMPRESSED");
    if (data.encrypted) throw ntfsError("EFS-encrypted stream (not supported).", "NTFS_ENCRYPTED");
    if (data.truncatedRuns) throw ntfsError("The $DATA run list does not cover the initialized size.", "NTFS_BAD_RUNS");
    if (data.resident) { sink(data.data.subarray(0, data.realSize)); return data.realSize; }
    const size = data.realSize;
    const init = Math.min(data.initSize ?? size, size);
    let off = 0;
    while (off < size) {
      if (isCancelled) isCancelled();
      const n = Math.min(chunkSize, size - off);
      const buf = Buffer.alloc(n);
      if (off < init) this._readRuns(data.runs, off, Math.min(n, init - off), buf, 0);
      sink(buf);
      off += n;
    }
    return size;
  }
}

/** Prefer the largest NTFS volume (skips a 100–500 MB System Reserved partition). */
function pickNtfsVolume(vols) {
  if (!vols.length) return null;
  return vols.reduce((best, v) => (Number(v.size) > Number(best.size) ? v : best));
}

/** Open the NTFS volume found on `disk` (largest, when more than one). */
function openFirstNtfsVolume(disk) {
  const vols = findNtfsVolumes(disk);
  if (!vols.length) throw ntfsError("No NTFS volume was found on this disk image (no NTFS boot sector at offset 0, in the MBR partitions, or in the GPT).", "NTFS_NOT_FOUND");
  const chosen = pickNtfsVolume(vols);
  return { volume: new NtfsVolume(disk, chosen.offset, chosen.size), volumes: vols, chosen };
}

module.exports = {
  NtfsVolume,
  findNtfsVolumes,
  openFirstNtfsVolume,
  pickNtfsVolume,
  applyFixup,
  parseRunList,
  ROOT_ENTRY,
  FIRST_USER_ENTRY,
};
