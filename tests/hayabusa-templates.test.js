// Templates for every Hayabusa CSV output, Hayabusa's level colors, and every Hayabusa timestamp
// format.
//
// electron/hayabusa-templates.json lists each dfir-timeline profile and the search,
// logon-summary, metrics and extract-base64 outputs with their timestamp columns. Timelines
// color each row by its rule level, the same in every color scheme. Hayabusa can
// write timestamps in eight formats; every one must display, sort and bucket as the same instant.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const DATA = require("../electron/hayabusa-templates.json");
const JUNTEI = require("../electron/juntei-templates.json");
const { detectFormatTemplate } = require("../electron/format-templates");
const backendNorm = require("../electron/utils/forensic-normalize");

let HAVE_SQLITE = false;
try { require("better-sqlite3")(":memory:").close(); HAVE_SQLITE = true; } catch { /* native module not built */ }
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module is not built for this Node runtime";

const T = DATA.templates;
const ALL = [...JUNTEI.templates, ...T];
const byName = (name) => T.find((t) => t.name === name);
const PROFILES = ["minimal", "standard", "verbose", "all-field-info", "all-field-info-verbose", "super-verbose", "timesketch-minimal", "timesketch-verbose"];

test("every Hayabusa output has a template, and each is well formed", () => {
  for (const p of PROFILES) assert.ok(byName(`Hayabusa ${p}`), `profile ${p}`);
  for (const n of ["search", "logon-summary (successful)", "logon-summary (failed)", "eid-metrics", "computer-metrics", "log-metrics", "extract-base64"]) {
    assert.ok(byName(`Hayabusa ${n}`), n);
  }
  for (const t of T) {
    const all = [...t.columns, ...(t.optionalColumns || [])];
    assert.equal(new Set(all).size, all.length, `${t.name}: no column listed twice`);
    for (const c of t.timestampColumns) assert.ok(all.includes(c), `${t.name}: ${c}`);
    if (t.levelColorColumn) assert.ok(t.columns.includes(t.levelColorColumn), `${t.name}: level column`);
  }
  // Rule dates, durations and the Timesketch description are not event times.
  assert.deepEqual(byName("Hayabusa super-verbose").timestampColumns, ["Timestamp"]);
  assert.deepEqual(byName("Hayabusa timesketch-verbose").timestampColumns, ["datetime"]);
  assert.deepEqual(byName("Hayabusa computer-metrics").timestampColumns, []);
  assert.deepEqual(byName("Hayabusa logon-summary (successful)").timestampColumns, ["First Logon", "Last Logon"]);
});

test("each output is recognized as its own template, with or without GeoIP columns, and no two tie", () => {
  for (const t of T) {
    for (const headers of [t.columns, [...t.columns].reverse(), [...t.columns, ...(t.optionalColumns || [])]]) {
      assert.equal(detectFormatTemplate(headers)?.name, t.name, `${t.name} from ${headers.length} columns`);
      const ties = ALL.filter((o) => o !== t && o.columns.length === t.columns.length
        && o.columns.every((c) => headers.includes(c))
        && (o.allowExtraColumns || headers.every((h) => [...o.columns, ...(o.optionalColumns || [])].includes(h))));
      assert.deepEqual(ties.map((o) => o.name), [], t.name);
    }
  }
  // A custom profile is not a template; it falls back to the name-based detection.
  assert.equal(detectFormatTemplate(["Timestamp", "RuleTitle", "Level", "Computer", "MyField"]), null);
});

test("the grid picks the same templates, and timelines get level colors", async () => {
  const { detectKapeProfile, HAYABUSA_LEVEL_COLORS } = await import("../src/utils/dataset-detect.js");
  for (const t of T) {
    const kp = detectKapeProfile(t.columns);
    assert.equal(kp?.name, t.name);
    assert.equal(kp.levelColorColumn, t.levelColorColumn, `${t.name}: level colors`);
  }
  for (const p of PROFILES) assert.equal(byName(`Hayabusa ${p}`).levelColorColumn, "Level", p);
  // Hayabusa CSVs from custom profiles still get the level colors.
  assert.equal(detectKapeProfile(["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID", "Details", "MyField"])?.levelColorColumn, "Level");
  assert.equal(HAYABUSA_LEVEL_COLORS, DATA.levelColors.levels);
});

test("level colors: white info, green low, yellow medium, orange high, red critical and emergency, black text, in every theme", async () => {
  const { buildLevelColorRules, compileColorRules, applyColors } = await import("../src/utils/color-rules.js");
  const compiled = compileColorRules(buildLevelColorRules("Level", DATA.levelColors.levels));
  const want = {
    info: ["#ffffff", "#000000"], informational: ["#ffffff", "#000000"],
    low: ["#00ff00", "#000000"],
    med: ["#ffff00", "#000000"], medium: ["#ffff00", "#000000"],
    high: ["#ffc100", "#000000"],
    crit: ["#ff0000", "#000000"], critical: ["#ff0000", "#000000"],
    emer: ["#ff0000", "#000000"], emergency: ["#ff0000", "#000000"],
  };
  for (const [level, [bg, fg]] of Object.entries(want)) {
    assert.deepEqual(applyColors({ Level: level }, compiled), { bg, fg }, level);
  }
  assert.equal(applyColors({ Level: "undef" }, compiled), null, "unknown levels keep the default colors");
  // The rules depend on nothing but the levels, so every color scheme shows the same colors.
  assert.equal(buildLevelColorRules.length, 2);
});

// One instant, 2017-08-30T19:13:38.198Z, in each of Hayabusa's time formats.
const INSTANT = Date.UTC(2017, 7, 30, 19, 13, 38, 198);
const FORMATS = {
  "default (local time)": "2017-08-31 04:13:38.198 +09:00",
  "-U": "2017-08-30 19:13:38.198 +00:00",
  "-O (ISO-8601)": "2017-08-30T19:13:38.198482Z",
  "--european-time": "31-08-2017 04:13:38.198 +09:00",
  "--us-time": "08-31-2017 04:13:38.198 AM +09:00",
  "--us-military-time": "08-31-2017 04:13:38.198 +09:00",
  "--rfc-2822": "Thu, 31 Aug 2017 04:13:38 +09:00",
  "--rfc-3339": "2017-08-31 04:13:38.198482+09:00",
  "-Z -06:00": "2017-08-30 13:13:38.198 -06:00",
};

test("every Hayabusa time format displays as the same instant (main process and grid)", async () => {
  const rendererNorm = await import("../src/utils/forensic-normalize.js");
  for (const [name, v] of Object.entries(FORMATS)) {
    const want = name === "--rfc-2822" ? INSTANT - 198 : INSTANT;
    assert.equal(backendNorm.normalizeTimestamp(v), want, `main: ${name}`);
    assert.equal(rendererNorm.normalizeTimestamp(v), want, `grid: ${name}`);
  }
  // 12-hour times: PM, noon and midnight.
  assert.equal(backendNorm.normalizeTimestamp("08-31-2017 04:13:38.198 PM +09:00"), INSTANT + 12 * 3600e3);
  assert.equal(backendNorm.normalizeTimestamp("08-31-2017 12:00:00.000 PM +00:00"), Date.UTC(2017, 7, 31, 12));
  assert.equal(backendNorm.normalizeTimestamp("08-31-2017 12:00:00.000 AM +00:00"), Date.UTC(2017, 7, 31, 0));
  // A European date whose day is 12 or less is read day first only for a day-first column.
  const eu = "03-08-2017 04:13:38.198 +09:00";
  assert.equal(backendNorm.normalizeTimestamp(eu, { dayFirst: true }), Date.UTC(2017, 7, 2, 19, 13, 38, 198));
  assert.equal(rendererNorm.normalizeTimestamp(eu, { dayFirst: true }), Date.UTC(2017, 7, 2, 19, 13, 38, 198));
  assert.equal(backendNorm.normalizeTimestamp(eu), Date.UTC(2017, 2, 7, 19, 13, 38, 198), "month first by default");
  const { formatDateTime } = await import("../src/utils/datetime.js");
  assert.equal(formatDateTime(eu, "yyyy-MM-dd HH:mm:ss.fff", "UTC", { dayFirst: true }), "2017-08-02 19:13:38.198");
});

test("every Hayabusa time format sorts and buckets as the same instant", () => {
  const fns = {};
  require("../electron/db/runtime-functions").registerRuntimeFunctions({ function: (n, o, f) => { fns[n] = f; } });
  for (const [name, v] of Object.entries(FORMATS)) {
    const sec = name === "--rfc-2822" ? "2017-08-30 19:13:38.000" : "2017-08-30 19:13:38.198";
    assert.equal(fns.sort_datetime(v), sec, `sort: ${name}`);
    assert.equal(fns.extract_datetime_minute(v), "2017-08-30 19:13", `minute: ${name}`);
    assert.equal(fns.extract_date(v), "2017-08-30", `date: ${name}`);
    assert.equal(fns.sort_datetime_dmy(v.replace("08-31-2017", "31-08-2017")), sec, `day-first sort: ${name}`);
  }
  assert.equal(fns.sort_datetime_dmy("03-08-2017 04:13:38.198 +09:00"), "2017-08-02 19:13:38.198");
  assert.equal(fns.extract_date_dmy("03-08-2017 04:13:38.198 +09:00"), "2017-08-02");
  assert.equal(fns.extract_datetime_minute_dmy("03-08-2017 04:13:38.198 +09:00"), "2017-08-02 19:13");
  // Naive month-first values keep their earlier keys.
  assert.equal(fns.sort_datetime("03/15/2024 08:30:00"), "2024-03-15 08:30:00");
  assert.equal(fns.sort_datetime("3/15/2024 2:00:00 PM"), "2024-03-15 14:00:00");
});

function hayabusaRows(format) {
  // Ten detections on 3 to 21 August 2017, out of order, as --european-time or --us-military-time.
  const days = [21, 3, 12, 5, 30, 1, 9, 14, 2, 11];
  return days.map((d, i) => {
    const dd = String(d).padStart(2, "0");
    const ts = format === "eu" ? `${dd}-08-2017 10:00:00.000 +00:00` : `08-${dd}-2017 10:00:00.000 +00:00`;
    return [ts, `Rule ${i}`, i % 2 ? "high" : "info", "PC", "Security", "4624", String(i), "x", "y", "id"];
  });
}

test("a European-format timeline is read day first everywhere, including by other threads", { skip }, () => {
  const TimelineDB = require("../electron/db");
  const std = byName("Hayabusa standard").columns;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-hayabusa-"));
  const db = new TimelineDB();
  const reader = new TimelineDB();
  try {
    db._dbPathHint = path.join(dir, "eu.db");
    db.createTab("eu", std);
    db.insertBatchArrays("eu", hayabusaRows("eu"));
    const done = db.finalizeImport("eu");
    assert.deepEqual(done.tsColumns, ["Timestamp"]);
    assert.deepEqual(done.dayFirstColumns, ["Timestamp"]);
    const days = (r) => r.rows.map((x) => x.Timestamp.slice(0, 2));
    const sorted = db.queryRows("eu", { offset: 0, limit: 20, sortCol: "Timestamp", sortDir: "asc" });
    assert.deepEqual(days(sorted), ["01", "02", "03", "05", "09", "11", "12", "14", "21", "30"]);
    const hist = db.getHistogramData("eu", "Timestamp");
    const buckets = (hist.data || hist).map((b) => b.day);
    assert.deepEqual(buckets.slice(0, 3), ["2017-08-01", "2017-08-02", "2017-08-03"]);
    const ranged = db.queryRows("eu", { offset: 0, limit: 20, dateRangeFilters: { Timestamp: { from: "2017-08-02", to: "2017-08-05 23:59:59" } } });
    assert.equal(ranged.totalFiltered, 3, "2, 3 and 5 August");

    // A query worker reopens the tab from its file and reads it the same way.
    reader.adoptTabFromFile("eu-reader", db.getTabWorkerDescriptor("eu"));
    assert.deepEqual([...reader.databases.get("eu-reader").dayFirstCols], ["Timestamp"]);
    const again = reader.queryRows("eu-reader", { offset: 0, limit: 20, sortCol: "Timestamp", sortDir: "desc" });
    assert.deepEqual(days(again), ["30", "21", "14", "12", "11", "09", "05", "03", "02", "01"]);

    // The US military format with the same dates stays month first.
    db.createTab("us", std);
    db.insertBatchArrays("us", hayabusaRows("us"));
    assert.deepEqual(db.finalizeImport("us").dayFirstColumns, []);
    const us = db.queryRows("us", { offset: 0, limit: 20, sortCol: "Timestamp", sortDir: "asc" });
    assert.deepEqual(us.rows.map((x) => x.Timestamp.slice(3, 5)), ["01", "02", "03", "05", "09", "11", "12", "14", "21", "30"]);
  } finally {
    reader.closeAll();
    db.closeAll();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the Hayabusa Templates page lists every template, its timestamp columns and level colors", () => {
  const page = fs.readFileSync(path.join(__dirname, "..", "docs", "reference", "hayabusa-templates.md"), "utf8");
  for (const t of T) {
    const row = page.split("\n").find((l) => l.startsWith(`| ${t.name} |`));
    assert.ok(row, `${t.name} has a row`);
    const cells = row.split(" | ");
    const ts = t.timestampColumns.length ? t.timestampColumns.map((c) => `\`${c}\``).join(", ") : "none";
    assert.equal(cells[cells.length - 2], ts, t.name);
    assert.equal(cells[cells.length - 1], `${t.levelColorColumn ? "Yes" : "No"} |`, t.name);
  }
  for (const l of DATA.levelColors.levels) {
    const row = page.split("\n").find((x) => x.startsWith(`| ${l.level} |`));
    assert.ok(row && row.includes(`\`${l.background}\``) && row.includes(`\`${l.text}\``), l.level);
  }
});
