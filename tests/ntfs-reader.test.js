// Read-only NTFS reader: partition discovery (raw / MBR / GPT), record fixups, path
// resolution, $DATA in every shape the extractor has to cope with (resident, fragmented,
// sparse, reverse-allocated, $ATTRIBUTE_LIST-split, initialized-size tails), and the
// records it must refuse or skip (compressed, encrypted, deleted, orphaned).

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { NtfsVolume, findNtfsVolumes, openFirstNtfsVolume, pickNtfsVolume, parseRunList, applyFixup } = require("../electron/parsers/ntfs-reader");
const { buildNtfsVolume, wrapMbr, wrapGpt, makeRecord, encodeRuns } = require("./helpers/ntfs-image-builder");

/** Wrap a Buffer as the disk interface the reader expects. */
function memDisk(buf) {
  return {
    virtualSize: buf.length,
    logicalSectorSize: 512,
    readAt(offset, length, out = null, outOffset = 0) {
      if (offset + length > buf.length) throw new Error("read past end");
      const b = out || Buffer.alloc(length);
      buf.copy(b, outOffset, offset, offset + length);
      return b;
    },
  };
}

function readAll(volume, file) {
  const chunks = [];
  volume.readFile(file, (c) => chunks.push(Buffer.from(c)));
  return Buffer.concat(chunks);
}

function fixture() {
  const big = crypto.randomBytes(3 * 4096 + 100);
  return buildNtfsVolume({
    files: [
      { name: "C", isDir: true },                                                   // 16
      { name: "Windows", isDir: true, parent: 16 },                                 // 17
      { name: "Security.evtx", parent: 17, content: big, runs: [{ clusters: 2 }, { clusters: 1, sparse: true }, { clusters: 2 }], reverseAlloc: true }, // 18
      { name: "readme.txt", parent: 16, content: "hello resident" },                // 19
      { name: "comp.bin", parent: 17, content: crypto.randomBytes(9000), compressed: true }, // 20
      { name: "gone.txt", parent: 16, content: "deleted", deleted: true },          // 21
      { name: "orphan.txt", parent: 17, content: "orphan", orphan: true },          // 22
      { name: "longfilename.txt", parent: 16, content: "dos+win32", dosName: "LONGFI~1.TXT" }, // 23
      { name: "split.bin", parent: 17, content: crypto.randomBytes(5 * 4096), runs: [{ clusters: 2 }, { clusters: 1 }, { clusters: 2 }], splitAttrList: true }, // 24
      { name: "init.bin", parent: 17, content: crypto.randomBytes(8192), initSize: 5000 }, // 25
      { name: "secret.bin", parent: 17, content: crypto.randomBytes(5000), encrypted: true }, // 26
      { name: "empty.txt", parent: 16, content: "" },                               // 27
    ],
  });
}

test("finds the NTFS volume behind a bare boot sector, an MBR and a GPT", () => {
  const { image } = fixture();
  assert.deepEqual(findNtfsVolumes(memDisk(image)).map((v) => [v.scheme, v.offset]), [["raw", 0]]);
  assert.deepEqual(findNtfsVolumes(memDisk(wrapMbr(image, { lba: 63 }))).map((v) => [v.scheme, v.offset]), [["mbr", 63 * 512]]);
  assert.deepEqual(findNtfsVolumes(memDisk(wrapGpt(image, { firstLba: 2048 }))).map((v) => [v.scheme, v.offset]), [["gpt", 2048 * 512]]);
  assert.deepEqual(findNtfsVolumes(memDisk(Buffer.alloc(4096))), []);
  assert.throws(() => openFirstNtfsVolume(memDisk(Buffer.alloc(4096))), (e) => e.code === "NTFS_NOT_FOUND");
});

test("accepts a DiscUtils-style boot sector without the 0x55AA trailer, and one with it", () => {
  const a = buildNtfsVolume({ files: [{ name: "x.txt", content: "a" }], withBootSignature: false });
  const b = buildNtfsVolume({ files: [{ name: "x.txt", content: "a" }], withBootSignature: true });
  assert.equal(findNtfsVolumes(memDisk(a.image)).length, 1);
  assert.equal(findNtfsVolumes(memDisk(b.image)).length, 1);
});

test("boot sector geometry is decoded and $MFT is bootstrapped from record 0", () => {
  const { image, clusterSize, mftLcn, recordCount } = fixture();
  const v = new NtfsVolume(memDisk(image), 0);
  assert.equal(v.clusterSize, clusterSize);
  assert.equal(v.recordSize, 1024);
  assert.equal(v.mftLcn, mftLcn);
  assert.equal(v.recordCount, recordCount);
  assert.deepEqual(v.mftRuns, [{ vcn: 0, lcn: mftLcn, clusters: (recordCount * 1024) / clusterSize }]);
});

test("lists live files with full backslash paths; deleted and orphaned records are excluded", () => {
  const fx = fixture();
  const v = new NtfsVolume(memDisk(wrapMbr(fx.image)), 63 * 512);
  const { files, orphans } = v.listFiles();
  const paths = files.map((f) => f.path).sort();
  assert.deepEqual(paths, [
    "C",
    "C\\Windows",
    "C\\Windows\\Security.evtx",
    "C\\Windows\\comp.bin",
    "C\\Windows\\init.bin",
    "C\\Windows\\secret.bin",
    "C\\Windows\\split.bin",
    "C\\empty.txt",
    "C\\longfilename.txt",
    "C\\readme.txt",
  ]);
  assert.equal(orphans, 1, "parent-sequence mismatch is an orphan");
  assert.ok(!paths.includes("C\\gone.txt"), "deleted record is skipped");
  assert.ok(!paths.includes("C\\LONGFI~1.TXT"), "Win32 name preferred over DOS name");
  const dir = files.find((f) => f.path === "C\\Windows");
  assert.equal(dir.isDir, true);
  assert.equal(dir.size, 0);
});

test("includeReserved exposes the metafiles under their root names", () => {
  const fx = fixture();
  const v = new NtfsVolume(memDisk(fx.image), 0);
  const { files } = v.listFiles({ includeReserved: true });
  const meta = files.filter((f) => f.entry < 16).map((f) => f.path);
  assert.ok(meta.includes("$MFT") && meta.includes("$LogFile") && meta.includes("$Extend"));
  const mft = files.find((f) => f.entry === 0);
  assert.equal(mft.size, fx.recordCount * 1024);
  assert.ok(readAll(v, mft).subarray(0, 4).toString("latin1") === "FILE");
});

test("reads every data shape back byte-for-byte", () => {
  const fx = fixture();
  const v = new NtfsVolume(memDisk(wrapGpt(fx.image)), 2048 * 512);
  const { files } = v.listFiles();
  const byName = Object.fromEntries(files.map((f) => [f.segments[f.segments.length - 1], f]));
  const spec = Object.fromEntries(fx.files.map((s) => [s.name, s]));

  const sec = byName["Security.evtx"];
  assert.equal(sec.sparse, true);
  assert.equal(sec.data.runs.length, 3);
  assert.equal(sec.data.runs[1].lcn, -1, "middle run is sparse");
  assert.ok(sec.data.runs[2].lcn < sec.data.runs[0].lcn, "reverse allocation produced a negative delta");
  assert.ok(readAll(v, sec).equals(spec["Security.evtx"].expected), "fragmented + sparse + reversed");

  assert.ok(readAll(v, byName["readme.txt"]).equals(Buffer.from("hello resident")), "resident");
  assert.equal(byName["readme.txt"].data.resident, true);
  assert.ok(readAll(v, byName["split.bin"]).equals(spec["split.bin"].expected), "$ATTRIBUTE_LIST-split runs");
  assert.equal(byName["split.bin"].size, 5 * 4096);
  assert.ok(readAll(v, byName["init.bin"]).equals(spec["init.bin"].expected), "bytes past initialized size read as zeros");
  assert.ok(readAll(v, byName["init.bin"]).subarray(5000).every((b) => b === 0));
  assert.equal(readAll(v, byName["empty.txt"]).length, 0);
  assert.ok(readAll(v, byName["longfilename.txt"]).equals(Buffer.from("dos+win32")));
});

test("compressed and encrypted streams are flagged and refused rather than misread", () => {
  const fx = fixture();
  const v = new NtfsVolume(memDisk(fx.image), 0);
  const { files } = v.listFiles();
  const comp = files.find((f) => f.path.endsWith("comp.bin"));
  const enc = files.find((f) => f.path.endsWith("secret.bin"));
  assert.equal(comp.compressed, true);
  assert.equal(enc.encrypted, true);
  assert.throws(() => readAll(v, comp), (e) => e.code === "NTFS_COMPRESSED");
  assert.throws(() => readAll(v, enc), (e) => e.code === "NTFS_ENCRYPTED");
});

test("readFile honours the chunk size and cancellation hook", () => {
  const fx = buildNtfsVolume({ files: [{ name: "big.bin", content: crypto.randomBytes(40000) }] });
  const v = new NtfsVolume(memDisk(fx.image), 0);
  const f = v.listFiles().files[0];
  const sizes = [];
  v.readFile(f, (c) => sizes.push(c.length), { chunkSize: 16384 });
  assert.deepEqual(sizes, [16384, 16384, 7232]);
  let calls = 0;
  assert.throws(() => v.readFile(f, () => {}, { chunkSize: 4096, isCancelled: () => { if (++calls === 3) throw Object.assign(new Error("stop"), { cancelled: true }); } }), (e) => e.cancelled === true);
});

test("run-list decoding: lengths, signed deltas, sparse runs, and a truncated list", () => {
  const buf = encodeRuns([{ lcn: 100, clusters: 3 }, { lcn: null, clusters: 2 }, { lcn: 90, clusters: 1 }, { lcn: 0x12345, clusters: 0x1FF }]);
  assert.deepEqual(parseRunList(buf, 0, 0), [
    { vcn: 0, lcn: 100, clusters: 3 },
    { vcn: 3, lcn: -1, clusters: 2 },
    { vcn: 5, lcn: 90, clusters: 1 },
    { vcn: 6, lcn: 0x12345, clusters: 0x1FF },
  ]);
  assert.deepEqual(parseRunList(buf.subarray(0, 2), 0, 7), [], "header without its bytes yields nothing");
  assert.deepEqual(parseRunList(encodeRuns([{ lcn: 5, clusters: 1 }]), 0, 42)[0].vcn, 42, "startVcn seeds the VCN");
});

test("fixups always use a 512-byte stride, even if the volume reports 4Kn sectors", () => {
  const rec = Buffer.alloc(4096, 0);
  rec.write("FILE", 0, 4, "latin1");
  rec.writeUInt16LE(48, 4);   // usa offset
  rec.writeUInt16LE(9, 6);    // usa count = 1 USN + 8 sectors
  rec.writeUInt16LE(0xABCD, 48);
  for (let i = 1; i < 9; i++) {
    rec.writeUInt16LE(0x1000 + i, 48 + i * 2); // original bytes
    rec.writeUInt16LE(0xABCD, i * 512 - 2);    // USN at each 512-byte tail
  }
  assert.equal(applyFixup(rec), true);
  for (let i = 1; i < 9; i++) {
    assert.equal(rec.readUInt16LE(i * 512 - 2), 0x1000 + i, `sector ${i} tail restored`);
  }
});

test("openFirstNtfsVolume prefers the largest partition on a multi-volume MBR disk", () => {
  const small = buildNtfsVolume({ files: [{ name: "bootmgr", content: "boot" }] });
  const large = buildNtfsVolume({
    files: [
      { name: "Windows", isDir: true },
      { name: "System32", isDir: true, parent: 16 },
      { name: "config", isDir: true, parent: 17 },
      { name: "SAM", parent: 18, content: crypto.randomBytes(4000) },
    ],
  });
  const lbaSmall = 63;
  const sectorsSmall = Math.ceil(small.image.length / 512);
  const lbaLarge = lbaSmall + sectorsSmall + 8;
  const sectorsLarge = Math.ceil(large.image.length / 512);
  const diskBuf = Buffer.alloc((lbaLarge + sectorsLarge + 1) * 512);
  diskBuf[446 + 4] = 0x07;
  diskBuf.writeUInt32LE(lbaSmall, 446 + 8);
  diskBuf.writeUInt32LE(sectorsSmall, 446 + 12);
  diskBuf[446 + 16 + 4] = 0x07;
  diskBuf.writeUInt32LE(lbaLarge, 446 + 16 + 8);
  diskBuf.writeUInt32LE(sectorsLarge, 446 + 16 + 12);
  diskBuf.writeUInt16LE(0xAA55, 510);
  small.image.copy(diskBuf, lbaSmall * 512);
  large.image.copy(diskBuf, lbaLarge * 512);
  const disk = memDisk(diskBuf);
  const vols = findNtfsVolumes(disk);
  assert.equal(vols.length, 2);
  assert.equal(pickNtfsVolume(vols).offset, lbaLarge * 512);
  const opened = openFirstNtfsVolume(disk);
  assert.equal(opened.chosen.offset, lbaLarge * 512);
  const names = opened.volume.listFiles().files.map((f) => f.segments[f.segments.length - 1]);
  assert.ok(names.includes("SAM"), `largest volume should contain SAM, got ${names.join(",")}`);
});

test("fixups are undone, and a torn record is detected", () => {
  const rec = makeRecord({ entry: 77, attrs: [] });
  const copy = Buffer.from(rec);
  assert.equal(copy.readUInt16LE(510), 0x1234, "sector tail carries the USN on disk");
  assert.equal(applyFixup(copy), true);
  assert.equal(copy.readUInt16LE(510), rec.readUInt16LE(48 + 2), "original bytes restored");
  const torn = Buffer.from(rec);
  torn.writeUInt16LE(0x9999, 1022);
  assert.equal(applyFixup(torn), false);
});
