// VHDX → triage collection: which files come out of the image, where they land, what is
// reported about the rest, and that the extracted folder then discovers exactly like a
// KAPE folder would. Also the selection rules on their own (pure) and the cancel /
// free-space guards.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { extractVhdxCollection, selectForTriage, planExtraction, sanitizeSegment } = require("../electron/parsers/vhdx-triage");
const { discoverTriageCollection } = require("../electron/analyzers/triage-collection");
const { buildNtfsVolume, wrapMbr, wrapRawInVhdx } = require("./helpers/ntfs-image-builder");

const CONSOLE_LOG = [
  "2025-04-22 22:51:48.1805116 | INF | Command line: --tsource C: --tdest D:\\out --target !SANS_Triage --vhdx WKSIT01",
  "2025-04-22 22:51:48.2000000 | INF | System info: Machine name: WKSIT01, 64-bit: true, User: admin OS: \"Windows10\" (10.0.19045)",
  "",
].join("\r\n");

const EVTX = Buffer.concat([Buffer.from("ElfFile\0"), crypto.randomBytes(70000)]);
const MFT_BLOB = Buffer.concat([Buffer.from("FILE"), crypto.randomBytes(20000)]);

/** A KAPE-shaped package: C\ tree + KAPE logs at the root, plus things that must NOT come out. */
function kapeImage() {
  return buildNtfsVolume({
    recordCount: 128,
    files: [
      { name: "C", isDir: true },                                                          // 16
      { name: "Windows", isDir: true, parent: 16 },                                        // 17
      { name: "System32", isDir: true, parent: 17 },                                       // 18
      { name: "winevt", isDir: true, parent: 18 },                                         // 19
      { name: "logs", isDir: true, parent: 19 },                                           // 20
      { name: "Security.evtx", parent: 20, content: EVTX, runs: [{ clusters: 9 }, { clusters: 9 }] }, // 21
      { name: "System.evtx", parent: 20, content: crypto.randomBytes(9000), compressed: true },        // 22
      { name: "config", isDir: true, parent: 18 },                                         // 23
      { name: "SYSTEM", parent: 23, content: crypto.randomBytes(5000) },                   // 24
      { name: "Prefetch", isDir: true, parent: 17 },                                       // 25
      { name: "CMD.EXE-0BD30981.pf", parent: 25, content: crypto.randomBytes(3000) },      // 26
      { name: "$MFT", parent: 16, content: MFT_BLOB },                                     // 27
      { name: "Users", isDir: true, parent: 16 },                                          // 28
      { name: "bob", isDir: true, parent: 28 },                                            // 29
      { name: "NTUSER.DAT", parent: 29, content: crypto.randomBytes(4200) },               // 30
      { name: "notes.docx", parent: 29, content: "not an artifact" },                      // 31
      { name: "out", isDir: true, parent: 16 },                                            // 32
      { name: "EvtxECmd_Output.csv", parent: 32, content: "TimeCreated,EventId,Channel,Provider\n2025-01-01,4624,Security,x\n" }, // 33
      { name: "2025-04-22T22_51_48_ConsoleLog.txt", content: CONSOLE_LOG },                // 34 (root)
      { name: "2025-04-22T22_51_48_CopyLog.csv", content: "SourceFile,DestinationFile\n" },// 35 (root)
      { name: "$Extend", isDir: true, parent: 5, entry: 40 },                              // container noise (root-level)
      { name: "$ObjId", parent: 40, content: "x", entry: 41 },
      { name: "gone.evtx", parent: 20, content: EVTX.subarray(0, 8000), deleted: true, entry: 42 },
    ],
  });
}

function writeVhdx(t, image, name = "kape.vhdx") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vhdx-triage-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const vhdx = path.join(dir, name);
  fs.writeFileSync(vhdx, wrapRawInVhdx(wrapMbr(image)));
  const out = path.join(dir, "out");
  fs.mkdirSync(out);
  return { vhdx, out, dir };
}

test("selectForTriage: the examiner Recycle Bin on a KAPE package is not evidence", () => {
  const f = (segments, extra = {}) => ({ segments, path: segments.join("\\"), isDir: false, entry: 100, ...extra });
  assert.equal(selectForTriage(f(["$Recycle.Bin", "S-1-5-21-1", "$IABC"])), null);
  assert.equal(selectForTriage(f(["C", "$Recycle.Bin", "S-1-5-21-1", "$IABC"])), "recyclebin");
  assert.equal(selectForTriage(f(["$Recycle.Bin", "S-1-5-21-1", "$IABC"]), { liveVolume: true }), "recyclebin");
});

test("selectForTriage: hive and browser transaction logs travel with the base file", () => {
  const f = (segments) => ({ segments, path: segments.join("\\"), isDir: false, entry: 100 });
  assert.equal(selectForTriage(f(["C", "Windows", "System32", "config", "SYSTEM.LOG1"])), "registryHive");
  assert.equal(selectForTriage(f(["C", "Users", "bob", "NTUSER.DAT.LOG1"])), "userHive");
  assert.equal(selectForTriage(f(["C", "Users", "bob", "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History-journal"])), "chromiumHistory");
});

test("selectForTriage: artifacts, KAPE logs and EZ CSVs come out; noise and unknowns stay", () => {
  const f = (segments, extra = {}) => ({ segments, path: segments.join("\\"), isDir: false, entry: 100, ...extra });
  assert.equal(selectForTriage(f(["C", "Windows", "System32", "winevt", "logs", "Security.evtx"])), "evtx");
  assert.equal(selectForTriage(f(["C", "$MFT"])), "mft");
  assert.equal(selectForTriage(f(["C", "Windows", "System32", "config", "SOFTWARE"])), "registryHive");
  assert.equal(selectForTriage(f(["C", "Users", "bob", "NTUSER.DAT"])), "userHive");
  assert.equal(selectForTriage(f(["2025_ConsoleLog.txt"])), "kapeLog");
  assert.equal(selectForTriage(f(["2025_SkipLog.csv.csv"])), "kapeLog");
  assert.equal(selectForTriage(f(["C", "out", "PECmd_Output.csv"])), "kapeCsv");
  assert.equal(selectForTriage(f(["C", "Users", "bob", "notes.docx"])), null);
  assert.equal(selectForTriage(f(["C", "out", "random.csv"])), null, "non-EZ CSV is not pre-selected");
  assert.equal(selectForTriage(f(["$Extend", "$UsnJrnl"])), null, "container metadata tree");
  assert.equal(selectForTriage(f(["System Volume Information", "x"])), null);
  assert.equal(selectForTriage(f(["C", "Windows"], { isDir: true })), null);
  // Reserved records: the container's own $MFT only counts for a live volume image.
  assert.equal(selectForTriage(f(["$MFT"], { entry: 0 })), null);
  assert.equal(selectForTriage(f(["$MFT"], { entry: 0 }), { liveVolume: true }), "mft");
  assert.equal(selectForTriage(f(["$LogFile"], { entry: 2 }), { liveVolume: true }), null);
});

test("planExtraction tells a KAPE package from a full volume image", () => {
  const kape = planExtraction([
    { segments: ["C"], path: "C", isDir: true, entry: 16, size: 0 },
    { segments: ["C", "$MFT"], path: "C\\$MFT", isDir: false, entry: 17, size: 10 },
    { segments: ["$MFT"], path: "$MFT", isDir: false, entry: 0, size: 99 },
  ]);
  assert.equal(kape.layout, "kape");
  assert.deepEqual(kape.byKind, { mft: 1 });
  assert.equal(kape.bytes, 10);
  const live = planExtraction([
    { segments: ["Windows"], path: "Windows", isDir: true, entry: 16, size: 0 },
    { segments: ["Windows", "System32"], path: "Windows\\System32", isDir: true, entry: 17, size: 0 },
    { segments: ["Windows", "System32", "config"], path: "Windows\\System32\\config", isDir: true, entry: 18, size: 0 },
    { segments: ["Windows", "System32", "config", "SAM"], path: "Windows\\System32\\config\\SAM", isDir: false, entry: 19, size: 5 },
    { segments: ["$MFT"], path: "$MFT", isDir: false, entry: 0, size: 99 },
  ]);
  assert.equal(live.layout, "volume");
  assert.deepEqual(live.byKind, { registryHive: 1, mft: 1 });
  assert.equal(live.bytes, 104);
});

test("sanitizeSegment keeps ordinary names and neutralises the dangerous ones", () => {
  assert.equal(sanitizeSegment("Microsoft-Windows-Sysmon%4Operational.evtx"), "Microsoft-Windows-Sysmon%4Operational.evtx");
  assert.equal(sanitizeSegment("a b!c"), "a b!c");
  assert.equal(sanitizeSegment(".."), "_.._");
  assert.equal(sanitizeSegment("."), "_._");
  assert.equal(sanitizeSegment("x\u0001y"), "x_y");
});

test("extracts the recognized artifacts into a mirrored tree and reports the rest", async (t) => {
  const fx = kapeImage();
  const { vhdx, out } = writeVhdx(t, fx.image);
  const progress = [];
  const r = await extractVhdxCollection(vhdx, out, { onProgress: (p) => progress.push(p.phase) });

  assert.equal(r.empty, false);
  assert.equal(r.volume.scheme, "mbr");
  assert.equal(r.volume.layout, "kape");
  assert.equal(r.vhdx.name, "kape.vhdx");
  assert.deepEqual(r.extracted.byKind, { evtx: 2, registryHive: 1, prefetch: 1, mft: 1, userHive: 1, kapeCsv: 1, kapeLog: 2 });
  assert.equal(r.extracted.count, 8, "the compressed evtx was selected but not written");
  assert.equal(r.skipped.compressed, 1);
  assert.deepEqual(r.skipped.failed.map((f) => f.path), ["C\\Windows\\System32\\winevt\\logs\\System.evtx"]);
  assert.equal(r.notSelected, 2, "notes.docx and the container's $Extend\\$ObjId stay in the image");
  assert.ok(r.warnings.some((w) => /1 NTFS-compressed file was skipped/.test(w)));
  assert.ok(progress.includes("scanning") && progress.includes("finalizing"));

  const spec = Object.fromEntries(fx.files.map((s) => [s.name, s]));
  const rel = (...p) => path.join(out, ...p);
  assert.ok(fs.readFileSync(rel("C", "Windows", "System32", "winevt", "logs", "Security.evtx")).equals(spec["Security.evtx"].expected));
  assert.ok(fs.readFileSync(rel("C", "$MFT")).equals(spec.$MFT.expected));
  assert.ok(fs.readFileSync(rel("C", "Windows", "System32", "config", "SYSTEM")).equals(spec.SYSTEM.expected));
  assert.ok(fs.readFileSync(rel("C", "Users", "bob", "NTUSER.DAT")).equals(spec["NTUSER.DAT"].expected));
  assert.equal(fs.readFileSync(rel("2025-04-22T22_51_48_ConsoleLog.txt"), "utf8"), CONSOLE_LOG);
  assert.ok(fs.existsSync(rel("C", "out", "EvtxECmd_Output.csv")));
  assert.ok(!fs.existsSync(rel("C", "Users", "bob", "notes.docx")), "unrecognized file not copied");
  assert.ok(!fs.existsSync(rel("C", "Windows", "System32", "winevt", "logs", "System.evtx")), "compressed file not written as garbage");
  assert.ok(!fs.existsSync(rel("C", "Windows", "System32", "winevt", "logs", "gone.evtx")), "deleted record not resurrected");
  assert.ok(!fs.existsSync(rel("$Extend")), "container metadata not copied");
  assert.ok(!fs.existsSync(rel("$MFT")), "the container's own $MFT is not evidence in a KAPE package");

  // The extracted folder is a normal triage collection from here on.
  const manifest = await discoverTriageCollection(out);
  assert.equal(manifest.error, undefined);
  assert.equal(manifest.kind, "both", "raw artifacts + an EvtxECmd CSV");
  const lm = manifest.lanes.lateralMovement.items.map((i) => i.name);
  assert.ok(lm.includes("Security"), lm.join(","));
  assert.equal(manifest.host.hostname, "WKSIT01", "live --tsource C: console log attributes the host");
  assert.deepEqual(manifest.artifacts.map((a) => a.kind).sort(), ["kapeCsv", "mft"]);
});

test("an image with no recognizable artifacts comes back empty without writing anything", async (t) => {
  const fx = buildNtfsVolume({ files: [{ name: "readme.txt", content: "nothing here" }] });
  const { vhdx, out } = writeVhdx(t, fx.image, "plain.vhdx");
  const r = await extractVhdxCollection(vhdx, out);
  assert.equal(r.empty, true);
  assert.equal(r.notSelected, 1);
  assert.deepEqual(fs.readdirSync(out), []);
});

test("cancellation aborts mid-copy and surfaces as a cancelled error", async (t) => {
  const fx = kapeImage();
  const { vhdx, out } = writeVhdx(t, fx.image);
  let ticks = 0;
  const isCancelled = () => { if (++ticks > 3) throw Object.assign(new Error("stop"), { cancelled: true }); };
  await assert.rejects(extractVhdxCollection(vhdx, out, { isCancelled }), (e) => e.cancelled === true);
});

test("refuses to start when the scratch volume lacks space", async (t) => {
  const fx = kapeImage();
  const { vhdx, out } = writeVhdx(t, fx.image);
  await assert.rejects(extractVhdxCollection(vhdx, out, { minFreeBytes: Number.MAX_SAFE_INTEGER / 4 }), (e) => e.code === "VHDX_NO_SPACE");
  assert.deepEqual(fs.readdirSync(out), [], "nothing written");
});

test("a non-VHDX or non-NTFS image fails with a clear error", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vhdx-triage-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const bogus = path.join(dir, "x.vhdx");
  fs.writeFileSync(bogus, Buffer.alloc(8192, 1));
  await assert.rejects(extractVhdxCollection(bogus, dir), /Not a VHDX file/);
  const noNtfs = path.join(dir, "blank.vhdx");
  fs.writeFileSync(noNtfs, wrapRawInVhdx(Buffer.alloc(2 * 1048576)));
  await assert.rejects(extractVhdxCollection(noNtfs, dir), (e) => e.code === "NTFS_NOT_FOUND");
});
