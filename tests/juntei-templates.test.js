// Templates for every Juntei CSV output.
//
// electron/juntei-templates.json lists each output's columns and, explicitly, its timestamp
// columns. A file that matches a template gets exactly those timestamp columns (no guessing from
// column names or values), and the grid picks the same template for its layout and status bar.

const test = require("node:test");
const assert = require("node:assert/strict");

const DATA = require("../electron/juntei-templates.json");
const { detectFormatTemplate } = require("../electron/format-templates");

let HAVE_SQLITE = false;
try { require("better-sqlite3")(":memory:").close(); HAVE_SQLITE = true; } catch { /* native module not built */ }
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module is not built for this Node runtime";

const T = DATA.templates;
const byName = (name) => T.find((t) => t.name === name);

test("every template is well formed", () => {
  assert.ok(T.length >= 55, `all Juntei outputs have a template (${T.length})`);
  assert.equal(new Set(T.map((t) => t.name)).size, T.length, "names are unique");
  for (const t of T) {
    assert.ok(t.name.startsWith("Juntei "), t.name);
    assert.ok(Array.isArray(t.producedBy) && t.producedBy.length > 0, `${t.name}: says which command writes it`);
    const all = [...t.columns, ...(t.optionalColumns || [])];
    assert.equal(new Set(all).size, all.length, `${t.name}: no column listed twice`);
    assert.ok(Array.isArray(t.timestampColumns), `${t.name}: timestamp columns are listed, even when none`);
    for (const c of t.timestampColumns) assert.ok(all.includes(c), `${t.name}: timestamp column ${c} is one of its columns`);
  }
});

test("each output is recognized as its own template, in any column order and with its optional columns", () => {
  for (const t of T) {
    for (const headers of [t.columns, [...t.columns].reverse(), [...t.columns, ...(t.optionalColumns || [])]]) {
      const found = detectFormatTemplate(headers);
      assert.equal(found?.name, t.name, `${t.name} from ${headers.length} columns`);
      const rivals = T.filter((o) => o !== t && o.columns.length === t.columns.length
        && o.columns.every((c) => headers.includes(c)) && (o.allowExtraColumns || headers.every((h) => [...o.columns, ...(o.optionalColumns || [])].includes(h))));
      assert.deepEqual(rivals.map((o) => o.name), [], `${t.name}: no other template ties with it`);
    }
  }
});

test("a file with a column the template doesn't list is not that output", () => {
  for (const t of T.filter((x) => !x.allowExtraColumns)) {
    assert.notEqual(detectFormatTemplate([...t.columns, "SomethingElse"])?.name, t.name, t.name);
  }
  assert.equal(detectFormatTemplate(["Timestamp", "Message"]), null);
  // Unknown SRUM tables keep the database's own columns after the common ones.
  const srum = byName("Juntei SRUM (other tables)");
  assert.equal(detectFormatTemplate([...srum.columns, "ProcessorTime"])?.name, srum.name);
});

test("the Juntei MFT CSV is recognized with its uSecZeros column", () => {
  // The header row exactly as `juntei parse-ntfs mft` writes it.
  const headers = ["EntryNum", "SN", "InUse", "ParentEntryNum", "ParentSN", "ParentPath", "File", "Ext", "Size",
    "RefCnt", "ReparseTarget", "Dir", "HasADS", "IsADS", "SI<FN", "uSecZeros", "Copied", "SI-Flags", "Type",
    "DataModified (SI)", "DataModified (FN)", "Accessed (SI)", "Accessed (FN)", "MetadataChanged (SI)",
    "MetadataChanged (FN)", "Created (SI)", "Created (FN)", "USN", "LogfileSN", "SID", "ObjectID-FileDroid",
    "LoggedUtilStream", "ZoneID-Contents", "SourceFile", "ParseErrors"];
  assert.equal(detectFormatTemplate(headers)?.name, "Juntei MFT");
  assert.ok(!byName("Juntei MFT").timestampColumns.includes("uSecZeros"), "uSecZeros is not a timestamp");
  // The earlier name for the column is no longer a Juntei MFT header.
  assert.notEqual(detectFormatTemplate(headers.map((h) => (h === "uSecZeros" ? "ZeroU-Secs" : h)))?.name, "Juntei MFT");
});

test("the grid picks the same template as the importer", async () => {
  const { detectFormatTemplate: rendererDetect, detectKapeProfile } = await import("../src/utils/dataset-detect.js");
  for (const t of T) {
    const headers = [...t.columns, ...(t.optionalColumns || [])];
    assert.equal(rendererDetect(headers)?.name, detectFormatTemplate(headers)?.name, t.name);
    assert.equal(detectKapeProfile(headers)?.name, t.name, `${t.name}: the status bar shows the template`);
    assert.equal(rendererDetect([...t.columns, "SomethingElse"])?.name, detectFormatTemplate([...t.columns, "SomethingElse"])?.name, `${t.name} + an unknown column`);
  }
  // Other tools' CSVs still get their own profiles.
  assert.equal(detectKapeProfile(["Timestamp", "RuleTitle", "Level", "Channel", "EventId", "RecordId", "Details"])?.name, "Hayabusa (Standard)");
});

test("columns that look like times but are not instants stay plain text", () => {
  const notTs = {
    "Juntei Registry Networks": ["FirstConnectedLocal", "LastConnectedLocal"],
    "Juntei Registry ShellBags": ["ItemModifiedUTC", "ItemCreatedUTC", "ItemAccessedUTC"],
    "Juntei Registry OpenSaveMRU": ["ItemModifiedUTC", "ItemCreatedUTC", "ItemAccessedUTC"],
    "Juntei $LogFile": ["RedoTimes", "UndoTimes"],
    "Juntei SRUM AppResourceUseInfo": ["ForegroundCycleTime", "BackgroundCycleTime", "FaceTime"],
    "Juntei SRUM NetworkConnections": ["ConnectedTime"],
    "Juntei Registry Dump": ["ValueData"],
    "Juntei auto-parse Manifest": ["OutputTimeZone", "DurationMs"],
  };
  for (const [name, cols] of Object.entries(notTs)) {
    const t = byName(name);
    assert.ok(t, name);
    for (const c of cols) {
      assert.ok([...t.columns, ...(t.optionalColumns || [])].includes(c), `${name} has ${c}`);
      assert.ok(!t.timestampColumns.includes(c), `${name}: ${c} is not a timestamp`);
    }
  }
  const ts = {
    "Juntei Registry Networks": ["FirstConnectedUTC", "LastConnectedUTC"],
    "Juntei Registry Amcache Files": ["LinkDate", "KeyLastWrittenUTC"],
    "Juntei Registry Amcache Devices": ["InstallDate", "FirstInstallDate", "DriverVerDate"],
    "Juntei MFT": ["Created (SI)", "Created (FN)", "DataModified (SI)", "MetadataChanged (FN)", "Accessed (SI)"],
    "Juntei Prefetch": ["LastRun", "PreviousRun1", "PreviousRun7", "VolumeCreated"],
    "Juntei SRUM EnergyUsage": ["Timestamp", "EventTimestamp"],
    "Juntei Registry Dump": ["KeyLastWrittenUTC", "ValueFiletimeUTC"],
  };
  for (const [name, cols] of Object.entries(ts)) {
    for (const c of cols) assert.ok(byName(name).timestampColumns.includes(c), `${name}: ${c} is a timestamp`);
  }
});

test("an imported Juntei CSV gets exactly the template's timestamp columns", { skip }, () => {
  const TimelineDB = require("../electron/db");
  const db = new TimelineDB();
  try {
    // Networks: the *Local columns hold timestamps but are wall-clock times, so they stay text;
    // a declared timestamp column is kept even when its sample values don't parse.
    const net = byName("Juntei Registry Networks");
    const created = db.createTab("net", net.columns);
    assert.deepEqual(new Set(created.tsColumns), new Set(net.timestampColumns));
    const rows = [];
    for (let i = 0; i < 20; i++) {
      rows.push(net.columns.map((c) => (c.endsWith("Local") ? "2026-10-13T00:52:42.941"
        : c === "LeaseObtainedUTC" ? "not a date" : c.endsWith("UTC") ? "2026-10-13T00:52:42Z" : `v${i}`)));
    }
    db.insertBatchArrays("net", rows);
    const done = db.finalizeImport("net");
    assert.deepEqual(new Set(done.tsColumns), new Set(net.timestampColumns));
    assert.equal(db.databases.get("net").formatTemplate, net.name);

    // Every template: the importer's timestamp columns are the template's, no more, no fewer.
    for (const t of T) {
      const headers = [...t.columns, ...(t.optionalColumns || [])];
      const id = `t${T.indexOf(t)}`;
      const r = db.createTab(id, headers);
      assert.deepEqual([...r.tsColumns].sort(), [...t.timestampColumns].sort(), t.name);
      db.closeTab(id);
    }

    // Any other file keeps the name-based detection.
    const other = db.createTab("other", ["EventTime", "StartType", "Message"]);
    assert.deepEqual(other.tsColumns.sort(), ["EventTime", "StartType"]);
    assert.equal(db.databases.get("other").formatTemplate, null);
  } finally {
    db.closeAll();
  }
});

test("the Juntei Templates page lists every template and its timestamp columns", () => {
  const page = require("node:fs").readFileSync(require("node:path").join(__dirname, "..", "docs", "reference", "juntei-templates.md"), "utf8");
  for (const t of T) {
    const row = page.split("\n").find((l) => l.startsWith(`| ${t.name} |`));
    assert.ok(row, `${t.name} has a row`);
    const listed = row.split(" | ").pop().replace(/ \|$/, "");
    assert.equal(listed, t.timestampColumns.length ? t.timestampColumns.map((c) => `\`${c}\``).join(", ") : "none", t.name);
  }
});
