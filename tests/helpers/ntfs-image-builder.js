// Synthetic NTFS volume + VHDX container builders for the disk-image reader tests.
//
// No NTFS formatter exists on macOS/CI, so the tests build a small but structurally honest
// volume by hand: a boot sector, a $MFT with real update-sequence fixups, $STANDARD_INFORMATION
// / $FILE_NAME / $DATA attributes, resident and non-resident data (fragmented, sparse, reverse-
// allocated runs), $ATTRIBUTE_LIST-split streams, and the record flags that mark deleted,
// compressed and orphaned files. The VHDX builder wraps any raw disk in a dynamic VHDX
// (spec-correct headers, region table, metadata, interleaved BAT, optional live log).

const { crc32c } = require("../../electron/parsers/vhdx");

const MB = 1048576;
const RECORD_SIZE = 1024;
const ROOT = 5;

// ── NTFS ───────────────────────────────────────────────────────────────────────────────

function align8(n) { return (n + 7) & ~7; }

function residentAttr(type, content, { flags = 0, id = 0 } = {}) {
  const contentOff = 24;
  const len = align8(contentOff + content.length);
  const b = Buffer.alloc(len);
  b.writeUInt32LE(type, 0);
  b.writeUInt32LE(len, 4);
  b[8] = 0;                       // resident
  b[9] = 0;                       // name length
  b.writeUInt16LE(0x18, 10);      // name offset
  b.writeUInt16LE(flags, 12);
  b.writeUInt16LE(id, 14);
  b.writeUInt32LE(content.length, 16);
  b.writeUInt16LE(contentOff, 20);
  content.copy(b, contentOff);
  return b;
}

/** Encode runs [{ lcn|null, clusters }] as an NTFS run list (relative, signed offsets). */
function encodeRuns(runs) {
  const parts = [];
  let prev = 0;
  for (const r of runs) {
    const lenBytes = intBytes(r.clusters, false);
    if (r.lcn == null) {
      parts.push(Buffer.from([lenBytes.length]), lenBytes);
      continue;
    }
    const delta = r.lcn - prev;
    prev = r.lcn;
    const offBytes = intBytes(delta, true);
    parts.push(Buffer.from([(offBytes.length << 4) | lenBytes.length]), lenBytes, offBytes);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function intBytes(v, signed) {
  let n = 1;
  if (signed) { while (v < -(2 ** (8 * n - 1)) || v >= 2 ** (8 * n - 1)) n++; } else { while (v >= 2 ** (8 * n)) n++; }
  const b = Buffer.alloc(n);
  let x = v < 0 ? v + 2 ** (8 * n) : v;
  for (let i = 0; i < n; i++) { b[i] = x % 256; x = Math.floor(x / 256); }
  return b;
}

function nonResidentAttr(type, { runs, startVcn, endVcn, allocSize, realSize, initSize, flags = 0, compressionUnit = 0, id = 0 }) {
  const runList = encodeRuns(runs);
  const runOff = 64;
  const len = align8(runOff + runList.length);
  const b = Buffer.alloc(len);
  b.writeUInt32LE(type, 0);
  b.writeUInt32LE(len, 4);
  b[8] = 1;                       // non-resident
  b[9] = 0;
  b.writeUInt16LE(0x40, 10);
  b.writeUInt16LE(flags, 12);
  b.writeUInt16LE(id, 14);
  b.writeBigUInt64LE(BigInt(startVcn), 16);
  b.writeBigUInt64LE(BigInt(endVcn), 24);
  b.writeUInt16LE(runOff, 32);
  b.writeUInt16LE(compressionUnit, 34);
  b.writeBigUInt64LE(BigInt(allocSize), 40);
  b.writeBigUInt64LE(BigInt(realSize), 48);
  b.writeBigUInt64LE(BigInt(initSize), 56);
  runList.copy(b, runOff);
  return b;
}

function stdInfoAttr() {
  return residentAttr(0x10, Buffer.alloc(48));
}

function fileNameAttr({ parentEntry, parentSeq, name, namespace = 1, isDir = false, realSize = 0 }) {
  const nameBuf = Buffer.from(name, "utf16le");
  const c = Buffer.alloc(66 + nameBuf.length);
  c.writeBigUInt64LE(BigInt(parentEntry) | (BigInt(parentSeq) << 48n), 0);
  c.writeBigUInt64LE(BigInt(realSize), 40);
  c.writeBigUInt64LE(BigInt(realSize), 48);
  c.writeUInt32LE(isDir ? 0x10000000 : 0x80, 56);
  c[64] = name.length;
  c[65] = namespace;
  nameBuf.copy(c, 66);
  return residentAttr(0x30, c);
}

function attrListAttr(entries) {
  const c = Buffer.alloc(32 * entries.length);
  entries.forEach((e, i) => {
    const o = i * 32;
    c.writeUInt32LE(e.type, o);
    c.writeUInt16LE(32, o + 4);
    c[o + 6] = 0;
    c[o + 7] = 0x20;
    c.writeBigUInt64LE(BigInt(e.startVcn || 0), o + 8);
    c.writeBigUInt64LE(BigInt(e.mftEntry) | (BigInt(e.seq || 1) << 48n), o + 16);
    c.writeUInt16LE(e.id || 0, o + 24);
  });
  return residentAttr(0x20, c);
}

/** Assemble a 1024-byte FILE record with real fixups (USN 0x1234 over both sectors). */
function makeRecord({ entry, seq = 1, inUse = true, isDir = false, baseEntry = 0, baseSeq = 0, attrs = [] }) {
  const b = Buffer.alloc(RECORD_SIZE);
  b.write("FILE", 0, "ascii");
  b.writeUInt16LE(48, 4);         // USA offset
  b.writeUInt16LE(3, 6);          // USA count (1 + 2 sectors)
  b.writeUInt16LE(seq, 16);
  b.writeUInt16LE(1, 18);
  b.writeUInt16LE(56, 20);        // first attribute
  b.writeUInt16LE((inUse ? 1 : 0) | (isDir ? 2 : 0), 22);
  b.writeUInt32LE(RECORD_SIZE, 28);
  b.writeBigUInt64LE(baseEntry ? (BigInt(baseEntry) | (BigInt(baseSeq) << 48n)) : 0n, 32);
  b.writeUInt16LE(attrs.length + 1, 40);
  b.writeUInt32LE(entry, 44);
  let pos = 56;
  for (const a of attrs) {
    if (pos + a.length + 8 > RECORD_SIZE - 8) throw new Error(`record ${entry} overflow`);
    a.copy(b, pos);
    pos += a.length;
  }
  b.writeUInt32LE(0xFFFFFFFF, pos);
  b.writeUInt32LE(pos + 8, 24);   // used size
  // Fixups: stash the real last two bytes of each 512-byte sector, replace them with the USN.
  const usn = 0x1234;
  b.writeUInt16LE(usn, 48);
  for (let i = 1; i <= 2; i++) {
    const end = i * 512 - 2;
    b.writeUInt16LE(b.readUInt16LE(end), 48 + i * 2);
    b.writeUInt16LE(usn, end);
  }
  return b;
}

function bootSector({ clusterSize, totalSectors, mftLcn, withSignature }) {
  const b = Buffer.alloc(512);
  if (withSignature) { b[0] = 0xEB; b[1] = 0x52; b[2] = 0x90; }
  b.write("NTFS    ", 3, "latin1");
  b.writeUInt16LE(512, 11);
  b[13] = clusterSize / 512;
  b[21] = 0xF8;
  b.writeBigUInt64LE(BigInt(totalSectors), 40);
  b.writeBigUInt64LE(BigInt(mftLcn), 48);
  b.writeBigUInt64LE(BigInt(mftLcn + 8), 56);
  b.writeInt8(-10, 64);           // 1024-byte records
  b.writeInt8(1, 68);
  b.writeBigUInt64LE(0x1122334455667788n, 72);
  if (withSignature) b.writeUInt16LE(0xAA55, 510);
  return b;
}

const META_NAMES = ["$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", ".", "$Bitmap", "$Boot", "$BadClus", "$Secure", "$UpCase", "$Extend"];

/**
 * Build a raw NTFS volume.
 *
 * @param {object} opts
 * @param {Array} opts.files  [{ name, parent (entry, default 5), isDir, content (Buffer|string),
 *   resident (default: content ≤ 600 bytes), runs: [{ clusters, sparse }] (fragment spec),
 *   reverseAlloc, compressed, encrypted, deleted, orphan (parent seq mismatch), namespace,
 *   dosName, splitAttrList, initSize }]
 *   Entries are assigned from 16 upward in order; `entry` is returned on each file.
 * @returns {{ image: Buffer, files: Array, clusterSize, mftLcn, recordCount }}
 */
function buildNtfsVolume({ files = [], clusterSize = 4096, recordCount = 96, withBootSignature = false } = {}) {
  const mftLcn = 4;
  const mftClusters = Math.ceil((recordCount * RECORD_SIZE) / clusterSize);
  let heap = mftLcn + mftClusters + 4;
  const allocations = []; // { lcn, buf }
  const alloc = (clusters, buf) => { const lcn = heap; heap += clusters; allocations.push({ lcn, buf }); return lcn; };

  const records = new Array(recordCount).fill(null);
  const specs = files.map((f, i) => ({ ...f, entry: f.entry ?? 16 + i, seq: f.seq ?? 1 }));
  const byEntry = new Map(specs.map((s) => [s.entry, s]));
  const seqOf = (entry) => (entry === ROOT || entry < 16) ? 1 : (byEntry.get(entry)?.seq ?? 1);

  // Reserved records 0–15 (0 is filled after the heap is known).
  for (let i = 1; i < 16; i++) {
    if (i >= META_NAMES.length) { records[i] = makeRecord({ entry: i, inUse: false }); continue; }
    const isDir = i === ROOT || META_NAMES[i] === "$Extend";
    records[i] = makeRecord({
      entry: i, isDir,
      attrs: [stdInfoAttr(), fileNameAttr({ parentEntry: ROOT, parentSeq: 1, name: META_NAMES[i], namespace: 3, isDir })],
    });
  }

  let nextExt = 16 + specs.length; // extension records go after the user records
  const out = [];
  for (const s of specs) {
    const parent = s.parent ?? ROOT;
    const parentSeq = s.orphan ? seqOf(parent) + 7 : seqOf(parent);
    const attrs = [stdInfoAttr()];
    if (s.dosName) attrs.push(fileNameAttr({ parentEntry: parent, parentSeq, name: s.dosName, namespace: 2, isDir: !!s.isDir }));
    attrs.push(fileNameAttr({ parentEntry: parent, parentSeq, name: s.name, namespace: s.namespace ?? 1, isDir: !!s.isDir, realSize: 0 }));

    let expected = Buffer.alloc(0);
    if (!s.isDir) {
      const content = Buffer.isBuffer(s.content) ? s.content : Buffer.from(s.content || "", "utf8");
      const resident = s.resident ?? content.length <= 600;
      const flags = (s.compressed ? 0x0001 : 0) | (s.encrypted ? 0x4000 : 0) | (s.runs?.some((r) => r.sparse) ? 0x8000 : 0);
      if (resident) {
        attrs.push(residentAttr(0x80, content, { flags }));
        expected = content;
      } else {
        const totalClusters = Math.max(1, Math.ceil(content.length / clusterSize));
        const runSpec = s.runs || [{ clusters: totalClusters }];
        const specTotal = runSpec.reduce((n, r) => n + r.clusters, 0);
        if (specTotal < totalClusters) throw new Error(`${s.name}: runs cover ${specTotal} clusters, content needs ${totalClusters}`);
        // Materialise the data per run; sparse runs read back as zeros.
        expected = Buffer.alloc(content.length);
        const runs = [];
        let vcn = 0;
        const order = runSpec.map((r, i) => i);
        if (s.reverseAlloc) order.reverse();
        const lcnFor = new Map();
        for (const i of order) {
          const r = runSpec[i];
          if (r.sparse) continue;
          const buf = Buffer.alloc(r.clusters * clusterSize);
          lcnFor.set(i, alloc(r.clusters, buf));
          heap += 1; // leave a gap so consecutive runs are never contiguous
        }
        for (let i = 0; i < runSpec.length; i++) {
          const r = runSpec[i];
          const from = vcn * clusterSize;
          if (r.sparse) {
            runs.push({ lcn: null, clusters: r.clusters });
          } else {
            const lcn = lcnFor.get(i);
            const slice = content.subarray(from, from + r.clusters * clusterSize);
            slice.copy(allocations.find((a) => a.lcn === lcn).buf, 0);
            slice.copy(expected, from);
            runs.push({ lcn, clusters: r.clusters });
          }
          vcn += r.clusters;
        }
        const allocSize = specTotal * clusterSize;
        const initSize = s.initSize ?? content.length;
        if (initSize < content.length) expected.fill(0, initSize);

        if (s.splitAttrList) {
          // Two fragments in two extension records; the base holds only the list.
          const mid = Math.ceil(runs.length / 2);
          const frags = [runs.slice(0, mid), runs.slice(mid)];
          let fragVcn = 0;
          const listEntries = [
            { type: 0x10, mftEntry: s.entry, seq: s.seq },
            { type: 0x30, mftEntry: s.entry, seq: s.seq },
          ];
          frags.forEach((fr, fi) => {
            const ext = nextExt++;
            const count = fr.reduce((n, r) => n + r.clusters, 0);
            const startVcn = fragVcn;
            const endVcn = fragVcn + count - 1;
            fragVcn += count;
            records[ext] = makeRecord({
              entry: ext, baseEntry: s.entry, baseSeq: s.seq,
              attrs: [nonResidentAttr(0x80, {
                runs: fr, startVcn, endVcn,
                allocSize: fi === 0 ? allocSize : 0, realSize: fi === 0 ? content.length : 0, initSize: fi === 0 ? initSize : 0, flags,
              })],
            });
            listEntries.push({ type: 0x80, startVcn, mftEntry: ext, seq: 1 });
          });
          attrs.splice(1, 0, attrListAttr(listEntries));
        } else {
          attrs.push(nonResidentAttr(0x80, {
            runs, startVcn: 0, endVcn: specTotal - 1, allocSize, realSize: content.length, initSize, flags,
            compressionUnit: s.compressed ? 4 : 0,
          }));
        }
      }
    }
    records[s.entry] = makeRecord({ entry: s.entry, seq: s.seq, inUse: !s.deleted, isDir: !!s.isDir, attrs });
    out.push({ ...s, expected });
  }

  const totalClusters = heap + 8;
  const totalSectors = totalClusters * (clusterSize / 512);
  const image = Buffer.alloc(totalClusters * clusterSize);
  bootSector({ clusterSize, totalSectors, mftLcn, withSignature: withBootSignature }).copy(image, 0);

  // $MFT record 0 — its $DATA covers the whole MFT region.
  records[0] = makeRecord({
    entry: 0,
    attrs: [
      stdInfoAttr(),
      fileNameAttr({ parentEntry: ROOT, parentSeq: 1, name: "$MFT", namespace: 3 }),
      nonResidentAttr(0x80, {
        runs: [{ lcn: mftLcn, clusters: mftClusters }], startVcn: 0, endVcn: mftClusters - 1,
        allocSize: mftClusters * clusterSize, realSize: recordCount * RECORD_SIZE, initSize: recordCount * RECORD_SIZE,
      }),
    ],
  });
  for (let i = 0; i < recordCount; i++) {
    const r = records[i] || makeRecord({ entry: i, inUse: false });
    r.copy(image, mftLcn * clusterSize + i * RECORD_SIZE);
  }
  for (const a of allocations) a.buf.copy(image, a.lcn * clusterSize);
  return { image, files: out, clusterSize, mftLcn, recordCount, totalClusters };
}

// ── Partition wrappers ─────────────────────────────────────────────────────────────────

function wrapMbr(volume, { lba = 63 } = {}) {
  const sectors = Math.ceil(volume.length / 512);
  const disk = Buffer.alloc((lba + sectors + 1) * 512);
  const e = 446;
  disk[e] = 0x80;
  disk[e + 4] = 0x07;
  disk.writeUInt32LE(lba, e + 8);
  disk.writeUInt32LE(sectors, e + 12);
  disk.writeUInt16LE(0xAA55, 510);
  volume.copy(disk, lba * 512);
  return disk;
}

function writeGuid(buf, off, guid) {
  const h = guid.replace(/-/g, "");
  buf.writeUInt32LE(parseInt(h.slice(0, 8), 16), off);
  buf.writeUInt16LE(parseInt(h.slice(8, 12), 16), off + 4);
  buf.writeUInt16LE(parseInt(h.slice(12, 16), 16), off + 6);
  Buffer.from(h.slice(16), "hex").copy(buf, off + 8);
}

function wrapGpt(volume, { firstLba = 2048 } = {}) {
  const sectors = Math.ceil(volume.length / 512);
  const totalSectors = firstLba + sectors + 40;
  const disk = Buffer.alloc(totalSectors * 512);
  // Protective MBR
  disk[446 + 4] = 0xEE;
  disk.writeUInt32LE(1, 446 + 8);
  disk.writeUInt32LE(totalSectors - 1, 446 + 12);
  disk.writeUInt16LE(0xAA55, 510);
  // GPT header at LBA 1
  const h = 512;
  disk.write("EFI PART", h, "latin1");
  disk.writeUInt32LE(0x00010000, h + 8);
  disk.writeUInt32LE(92, h + 12);
  disk.writeBigUInt64LE(1n, h + 24);
  disk.writeBigUInt64LE(BigInt(totalSectors - 1), h + 32);
  disk.writeBigUInt64LE(BigInt(firstLba), h + 40);
  disk.writeBigUInt64LE(BigInt(firstLba + sectors - 1), h + 48);
  disk.writeBigUInt64LE(2n, h + 72);
  disk.writeUInt32LE(128, h + 80);
  disk.writeUInt32LE(128, h + 84);
  // Entry 0 at LBA 2: Microsoft basic data
  const e = 1024;
  writeGuid(disk, e, "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7");
  writeGuid(disk, e + 16, "12345678-1234-1234-1234-123456789abc");
  disk.writeBigUInt64LE(BigInt(firstLba), e + 32);
  disk.writeBigUInt64LE(BigInt(firstLba + sectors - 1), e + 40);
  volume.copy(disk, firstLba * 512);
  return disk;
}

// ── VHDX container ─────────────────────────────────────────────────────────────────────

const G = {
  BAT: "2dc27766-f623-4200-9d64-115e9bfd4a08",
  METADATA: "8b7ca206-4790-4b9a-b8fe-575f050f886e",
  FILE_PARAMETERS: "caa16737-fa36-4d43-b3b6-33f0aa44e76b",
  VIRTUAL_DISK_SIZE: "2fa54224-cd1b-4876-b211-5dbed83bf4b8",
  LOGICAL_SECTOR_SIZE: "8141bf1d-a96f-4709-ba47-f233a8faab5f",
  PHYSICAL_SECTOR_SIZE: "cda348c7-445d-4471-9cc9-e9885251c556",
  PAGE83: "beca12ab-b2e6-4523-93ef-c309e000c746",
};

/**
 * Build a dynamic VHDX.
 *
 * @param {object} opts
 * @param {number} opts.virtualSize
 * @param {number} [opts.blockSize=1MB]
 * @param {Map<number, Buffer>} [opts.blocks]  block index → content (missing = NOT_PRESENT)
 * @param {Set<number>} [opts.zeroBlocks]      block indexes marked PAYLOAD_BLOCK_ZERO
 * @param {boolean} [opts.corruptHeader1]      flip a byte in header 1 (checksum fails)
 * @param {boolean} [opts.corruptHeader2]
 * @param {boolean} [opts.hasParent]           mark as differencing
 * @param {Array} [opts.logEntries]            [{ descriptors: [{ kind: "data", fileOffset, sector(4096) } | { kind: "zero", fileOffset, length }] }]
 * @param {string} [opts.creator="TLE test builder"]
 */
function buildVhdx({
  virtualSize, blockSize = MB, blocks = new Map(), zeroBlocks = new Set(),
  corruptHeader1 = false, corruptHeader2 = false, hasParent = false, logEntries = null, creator = "TLE test builder",
  logicalSectorSize = 512,
} = {}) {
  const chunkRatio = Math.floor((2 ** 23 * logicalSectorSize) / blockSize);
  const dataBlocks = Math.ceil(virtualSize / blockSize);
  const totalEntries = dataBlocks + Math.floor((dataBlocks - 1) / chunkRatio);
  const batRegionLen = Math.max(MB, Math.ceil((totalEntries * 8) / MB) * MB);
  const LOG_OFF = 1 * MB, LOG_LEN = 1 * MB;
  const META_OFF = 2 * MB, META_LEN = 1 * MB;
  const BAT_OFF = 3 * MB;
  const DATA_OFF = BAT_OFF + batRegionLen;

  const present = [...blocks.keys()].sort((a, b) => a - b);
  const fileSize = DATA_OFF + present.length * blockSize;
  const file = Buffer.alloc(fileSize);

  // File type identifier
  file.write("vhdxfile", 0, "latin1");
  Buffer.from(creator, "utf16le").copy(file, 8);

  // Headers
  const logGuid = logEntries ? "0f0e0d0c-0b0a-0908-0706-050403020100" : "00000000-0000-0000-0000-000000000000";
  const header = (seq) => {
    const h = Buffer.alloc(4096);
    h.write("head", 0, "latin1");
    h.writeBigUInt64LE(BigInt(seq), 8);
    writeGuid(h, 16, "11111111-2222-3333-4444-555555555555");
    writeGuid(h, 32, "66666666-7777-8888-9999-aaaaaaaaaaaa");
    writeGuid(h, 48, logGuid);
    h.writeUInt16LE(0, 64);
    h.writeUInt16LE(1, 66);
    h.writeUInt32LE(LOG_LEN, 68);
    h.writeBigUInt64LE(BigInt(LOG_OFF), 72);
    h.writeUInt32LE(crc32c(h, 4), 4);
    return h;
  };
  const h1 = header(1), h2 = header(2);
  if (corruptHeader1) h1[100] ^= 0xFF;
  if (corruptHeader2) h2[100] ^= 0xFF;
  h1.copy(file, 64 * 1024);
  h2.copy(file, 128 * 1024);

  // Region table (×2)
  const rt = Buffer.alloc(64 * 1024);
  rt.write("regi", 0, "latin1");
  rt.writeUInt32LE(2, 8);
  writeGuid(rt, 16, G.METADATA); rt.writeBigUInt64LE(BigInt(META_OFF), 32); rt.writeUInt32LE(META_LEN, 40); rt.writeUInt32LE(1, 44);
  writeGuid(rt, 48, G.BAT); rt.writeBigUInt64LE(BigInt(BAT_OFF), 64); rt.writeUInt32LE(batRegionLen, 72); rt.writeUInt32LE(1, 76);
  rt.writeUInt32LE(crc32c(rt, 4), 4);
  rt.copy(file, 192 * 1024);
  rt.copy(file, 256 * 1024);

  // Metadata
  const meta = Buffer.alloc(META_LEN);
  meta.write("metadata", 0, "latin1");
  const items = [
    { guid: G.FILE_PARAMETERS, flags: 4, data: (() => { const b = Buffer.alloc(8); b.writeUInt32LE(blockSize, 0); b.writeUInt32LE(hasParent ? 2 : 0, 4); return b; })() },
    { guid: G.VIRTUAL_DISK_SIZE, flags: 6, data: (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(virtualSize), 0); return b; })() },
    { guid: G.PAGE83, flags: 6, data: Buffer.from("5fd1dce848dc1a49ae58a45fa7857c7b", "hex") },
    { guid: G.LOGICAL_SECTOR_SIZE, flags: 6, data: (() => { const b = Buffer.alloc(4); b.writeUInt32LE(logicalSectorSize, 0); return b; })() },
    { guid: G.PHYSICAL_SECTOR_SIZE, flags: 6, data: (() => { const b = Buffer.alloc(4); b.writeUInt32LE(4096, 0); return b; })() },
  ];
  meta.writeUInt16LE(items.length, 10);
  let itemOff = 0x10000;
  items.forEach((it, i) => {
    const e = 32 + i * 32;
    writeGuid(meta, e, it.guid);
    meta.writeUInt32LE(itemOff, e + 16);
    meta.writeUInt32LE(it.data.length, e + 20);
    meta.writeUInt32LE(it.flags, e + 24);
    it.data.copy(meta, itemOff);
    itemOff += it.data.length;
  });
  meta.copy(file, META_OFF);

  // BAT + blocks
  const bat = Buffer.alloc(batRegionLen);
  present.forEach((idx, k) => {
    const fileOff = DATA_OFF + k * blockSize;
    const batIndex = idx + Math.floor(idx / chunkRatio);
    bat.writeBigUInt64LE(6n | (BigInt(fileOff / MB) << 20n), batIndex * 8);
    blocks.get(idx).copy(file, fileOff, 0, Math.min(blockSize, blocks.get(idx).length));
  });
  for (const idx of zeroBlocks) {
    const batIndex = idx + Math.floor(idx / chunkRatio);
    bat.writeBigUInt64LE(2n, batIndex * 8);
  }
  bat.copy(file, BAT_OFF);

  // Log
  if (logEntries) {
    let off = 0;
    let seq = 1n;
    const tail = 0;
    for (const entry of logEntries) {
      const descs = entry.descriptors;
      const dataCount = descs.filter((d) => d.kind === "data").length;
      const headLen = Math.ceil((64 + descs.length * 32) / 4096) * 4096;
      const entryLen = headLen + dataCount * 4096;
      const e = Buffer.alloc(entryLen);
      e.write("loge", 0, "latin1");
      e.writeUInt32LE(entryLen, 8);
      e.writeUInt32LE(tail, 12);
      e.writeBigUInt64LE(seq, 16);
      e.writeUInt32LE(descs.length, 24);
      writeGuid(e, 32, logGuid);
      e.writeBigUInt64LE(BigInt(fileSize), 48);
      e.writeBigUInt64LE(BigInt(fileSize), 56);
      let di = 0;
      descs.forEach((d, i) => {
        const o = 64 + i * 32;
        if (d.kind === "zero") {
          e.write("zero", o, "latin1");
          e.writeBigUInt64LE(BigInt(d.length), o + 8);
          e.writeBigUInt64LE(BigInt(d.fileOffset), o + 16);
          e.writeBigUInt64LE(seq, o + 24);
        } else {
          const s = d.sector;
          e.write("desc", o, "latin1");
          s.copy(e, o + 4, 4092, 4096);     // TrailingBytes
          s.copy(e, o + 8, 0, 8);           // LeadingBytes
          e.writeBigUInt64LE(BigInt(d.fileOffset), o + 16);
          e.writeBigUInt64LE(seq, o + 24);
          const ds = headLen + di * 4096;
          di++;
          e.write("data", ds, "latin1");
          e.writeUInt32LE(Number(seq >> 32n), ds + 4);
          s.copy(e, ds + 8, 8, 4092);
          e.writeUInt32LE(Number(seq & 0xFFFFFFFFn), ds + 4092);
        }
      });
      e.writeUInt32LE(crc32c(e, 4), 4);
      e.copy(file, LOG_OFF + off);
      off += entryLen;
      seq += 1n;
    }
  }
  return file;
}

/** Wrap a raw disk image in a VHDX, block by block (all-zero blocks become ZERO entries). */
function wrapRawInVhdx(raw, { blockSize = MB, ...rest } = {}) {
  const blocks = new Map();
  const zeroBlocks = new Set();
  const count = Math.ceil(raw.length / blockSize);
  for (let i = 0; i < count; i++) {
    const chunk = raw.subarray(i * blockSize, (i + 1) * blockSize);
    if (chunk.every((b) => b === 0)) zeroBlocks.add(i);
    else { const b = Buffer.alloc(blockSize); chunk.copy(b); blocks.set(i, b); }
  }
  return buildVhdx({ virtualSize: count * blockSize, blockSize, blocks, zeroBlocks, ...rest });
}

module.exports = {
  buildNtfsVolume, wrapMbr, wrapGpt, buildVhdx, wrapRawInVhdx, writeGuid, makeRecord, encodeRuns, MB, RECORD_SIZE,
};
