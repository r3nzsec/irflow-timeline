// VHDX container reader: header/region/metadata parsing, BAT translation (including the
// interleaved sector-bitmap slots), zero/absent blocks, checksum fallbacks, refusal of
// differencing disks, and in-memory log replay.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { openVhdx, isVhdxFile, crc32c, readGuid } = require("../electron/parsers/vhdx");
const { buildVhdx, wrapRawInVhdx, writeGuid, MB } = require("./helpers/ntfs-image-builder");

function tmpFile(t, name, buf) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vhdx-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const p = path.join(dir, name);
  fs.writeFileSync(p, buf);
  return p;
}

test("crc32c matches the Castagnoli check value", () => {
  assert.equal(crc32c(Buffer.from("123456789")).toString(16), "e3069283");
});

test("readGuid renders the mixed-endian on-disk form canonically", () => {
  const b = Buffer.alloc(16);
  writeGuid(b, 0, "2dc27766-f623-4200-9d64-115e9bfd4a08");
  assert.equal(readGuid(b, 0), "2dc27766-f623-4200-9d64-115e9bfd4a08");
});

test("reads back a raw image wrapped block by block, across block boundaries and zero blocks", (t) => {
  const raw = Buffer.alloc(4 * MB);
  crypto.randomBytes(MB).copy(raw, 0);              // block 0: data
  // block 1: all zero → ZERO entry
  crypto.randomBytes(MB).copy(raw, 2 * MB);         // block 2: data
  // block 3: zero
  const file = tmpFile(t, "wrap.vhdx", wrapRawInVhdx(raw, { blockSize: MB }));
  assert.equal(isVhdxFile(file), true);
  const d = openVhdx(file);
  try {
    assert.equal(d.virtualSize, 4 * MB);
    assert.equal(d.blockSize, MB);
    assert.equal(d.dataBlocks, 4);
    assert.equal(d.allocatedBlocks, 2);
    assert.deepEqual(d.warnings, []);
    // Whole-disk read equals the source.
    assert.ok(d.readAt(0, 4 * MB).equals(raw));
    // A read spanning data→zero→data boundaries.
    const span = d.readAt(MB - 1000, 2 * MB + 2000);
    assert.ok(span.equals(raw.subarray(MB - 1000, 3 * MB + 1000)));
    // Inside a zero block.
    assert.ok(d.readAt(MB + 10, 500).every((b) => b === 0));
    // Into a caller-supplied buffer at an offset.
    const out = Buffer.alloc(100, 0xAA);
    d.readAt(2 * MB + 5, 50, out, 25);
    assert.ok(out.subarray(25, 75).equals(raw.subarray(2 * MB + 5, 2 * MB + 55)));
    assert.equal(out[24], 0xAA);
    assert.equal(out[75], 0xAA);
  } finally { d.close(); }
});

test("range checks reject reads past the virtual disk", (t) => {
  const file = tmpFile(t, "range.vhdx", wrapRawInVhdx(Buffer.alloc(MB, 1)));
  const d = openVhdx(file);
  try {
    assert.throws(() => d.readAt(MB - 10, 20), (e) => e.code === "VHDX_RANGE");
    assert.throws(() => d.readAt(-1, 1), (e) => e.code === "VHDX_RANGE");
  } finally { d.close(); }
});

test("falls back to the second header when the first is corrupt, and refuses when both are", (t) => {
  const blocks = new Map([[0, Buffer.alloc(MB, 7)]]);
  const ok = tmpFile(t, "h1.vhdx", buildVhdx({ virtualSize: MB, blocks, corruptHeader1: true }));
  const d = openVhdx(ok);
  try { assert.equal(d.readAt(0, 1)[0], 7); } finally { d.close(); }
  const bad = tmpFile(t, "h12.vhdx", buildVhdx({ virtualSize: MB, blocks, corruptHeader1: true, corruptHeader2: true }));
  assert.throws(() => openVhdx(bad), /header is corrupt/);
});

test("rejects non-VHDX files and differencing disks", (t) => {
  const notVhdx = tmpFile(t, "x.vhdx", Buffer.from("conectix" + "x".repeat(4096)));
  assert.throws(() => openVhdx(notVhdx), (e) => e.code === "VHDX_NOT_VHDX");
  assert.equal(isVhdxFile(notVhdx), false);
  const diff = tmpFile(t, "diff.vhdx", buildVhdx({ virtualSize: MB, blocks: new Map([[0, Buffer.alloc(MB)]]), hasParent: true }));
  assert.throws(() => openVhdx(diff), (e) => e.code === "VHDX_DIFFERENCING");
});

test("BAT lookups skip the interleaved sector-bitmap entry after each chunk", (t) => {
  // 1 MB blocks → chunkRatio 4096, so block 4096 sits at BAT index 4097. The file only
  // stores the two present blocks; the other 4095 are NOT_PRESENT.
  const chunkRatio = 4096;
  const a = Buffer.alloc(MB, 0x11), b = Buffer.alloc(MB, 0x22);
  const file = tmpFile(t, "chunk.vhdx", buildVhdx({
    virtualSize: (chunkRatio + 1) * MB, blockSize: MB, blocks: new Map([[0, a], [chunkRatio, b]]),
  }));
  const d = openVhdx(file);
  try {
    assert.equal(d.dataBlocks, chunkRatio + 1);
    assert.equal(d.allocatedBlocks, 2);
    assert.equal(d.readAt(0, 4)[0], 0x11);
    assert.equal(d.readAt(chunkRatio * MB + 123, 4)[0], 0x22);
    assert.ok(d.readAt(10 * MB, 64).every((x) => x === 0));
  } finally { d.close(); }
});

test("replays a live log in memory: data sectors override the file, zero descriptors clear it", (t) => {
  const block = crypto.randomBytes(MB);
  const noLog = buildVhdx({ virtualSize: MB, blocks: new Map([[0, block]]) });
  // Find where block 0 lives in the file so the log can target it.
  const blockFileOffset = noLog.indexOf(block.subarray(0, 64));
  assert.ok(blockFileOffset > 0);

  const replacement = crypto.randomBytes(4096);
  const file = tmpFile(t, "log.vhdx", buildVhdx({
    virtualSize: MB,
    blocks: new Map([[0, block]]),
    logEntries: [{
      descriptors: [
        { kind: "data", fileOffset: blockFileOffset + 8192, sector: replacement },
        { kind: "zero", fileOffset: blockFileOffset + 4 * 4096, length: 4096 },
      ],
    }],
  }));
  const d = openVhdx(file);
  try {
    assert.equal(d.warnings.length, 1);
    assert.match(d.warnings[0], /not cleanly detached; 2 logged writes were replayed/);
    const got = d.readAt(0, MB);
    assert.ok(got.subarray(0, 8192).equals(block.subarray(0, 8192)), "untouched sectors unchanged");
    assert.ok(got.subarray(8192, 12288).equals(replacement), "logged data sector replayed");
    assert.ok(got.subarray(4 * 4096, 5 * 4096).every((x) => x === 0), "zero descriptor applied");
    assert.ok(got.subarray(5 * 4096).equals(block.subarray(5 * 4096)), "rest unchanged");
    // A partial read straddling the replayed sector sees the overlay too.
    const straddle = d.readAt(8000, 400);
    assert.ok(straddle.subarray(0, 192).equals(block.subarray(8000, 8192)));
    assert.ok(straddle.subarray(192).equals(replacement.subarray(0, 208)));
  } finally { d.close(); }
});

test("a live LogGuid with an empty log region is reported, not fatal", (t) => {
  const built = buildVhdx({ virtualSize: MB, blocks: new Map([[0, Buffer.alloc(MB, 3)]]), logEntries: [] });
  const file = tmpFile(t, "emptylog.vhdx", built);
  const d = openVhdx(file);
  try {
    assert.equal(d.readAt(0, 1)[0], 3);
    assert.match(d.warnings[0], /no valid log entries/);
  } finally { d.close(); }
});
