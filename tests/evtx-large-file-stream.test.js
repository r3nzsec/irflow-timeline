const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  _iterateEvtxRecords,
  EVTX_FILE_HEADER_BYTES,
  EVTX_CHUNK_BYTES,
} = require("../electron/parsers/evtx");

test("EVTX reader keeps reads bounded at the 4,109,438,976-byte issue #22 size", async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-evtx-large-"));
  const filePath = path.join(tempDir, "Security.evtx");
  const fileSize = 4_109_438_976;
  const fd = fs.openSync(filePath, "w");
  fs.writeSync(fd, Buffer.alloc(EVTX_FILE_HEADER_BYTES + EVTX_CHUNK_BYTES), 0);
  fs.ftruncateSync(fd, fileSize); // sparse: logical size >2 GiB, physical allocation stays tiny
  fs.closeSync(fd);
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  const readerSizes = [];
  class BinaryReader {
    constructor(buffer) {
      readerSizes.push(buffer.byteLength);
    }
  }
  class FileHeader {
    verify() { return true; }
    chunkCount() { return 1; }
  }
  class ChunkHeader {
    checkMagic() { return true; }
    *records() {
      yield { id: 1 };
      yield { id: 2 };
    }
  }

  const records = [];
  for await (const item of _iterateEvtxRecords(filePath, { BinaryReader, FileHeader, ChunkHeader })) {
    records.push(item);
  }

  assert.equal(fs.statSync(filePath).size, fileSize);
  assert.deepEqual(records.map(({ record }) => record.id), [1, 2]);
  assert.deepEqual(readerSizes, [EVTX_FILE_HEADER_BYTES, EVTX_CHUNK_BYTES]);
  assert.equal(records[0].bytesRead, EVTX_FILE_HEADER_BYTES + EVTX_CHUNK_BYTES);
});

test("EVTX reader rejects an incomplete header with a forensic format error", async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-evtx-short-"));
  const filePath = path.join(tempDir, "truncated.evtx");
  fs.writeFileSync(filePath, Buffer.alloc(128));
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  class BinaryReader {}
  class FileHeader {}
  class ChunkHeader {}

  await assert.rejects(async () => {
    for await (const _item of _iterateEvtxRecords(filePath, { BinaryReader, FileHeader, ChunkHeader })) {
      // No records are expected.
    }
  }, /incomplete file header/);
});
