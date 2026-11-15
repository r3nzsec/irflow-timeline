const test = require("node:test");
const assert = require("node:assert/strict");

const FORMAT = "yyyy-MM-dd HH:mm:ss.fffffff";
const load = () => import("../src/utils/datetime.js");

test("seven-digit display preserves Hayabusa -O fractions, including leading zeroes", async () => {
  const { formatDateTime } = await load();
  for (const fraction of ["1234567", "0000001", "0004567", "9999999", "2001668"]) {
    const raw = `2026-10-20T06:34:50.${fraction}Z`;
    assert.equal(formatDateTime(raw, FORMAT, "UTC"), `2026-10-20 06:34:50.${fraction}`);
    assert.equal(formatDateTime(raw, "", "UTC"), raw, "raw mode retains the original value");
    assert.equal(formatDateTime(raw, "yyyy-MM-dd HH:mm:ss.fff", "UTC"),
      `2026-10-20 06:34:50.${fraction.slice(0, 3)}`);
  }
});

test("fraction formatting pads short inputs and truncates nanoseconds without rounding", async () => {
  const { formatDateTime } = await load();
  for (const [fraction, expected] of [
    ["1", "1000000"], ["12", "1200000"], ["123", "1230000"],
    ["123456", "1234560"], ["123456789", "1234567"], ["999999999", "9999999"],
  ]) {
    assert.equal(formatDateTime(`2026-10-20T06:34:50.${fraction}Z`, FORMAT, "UTC"),
      `2026-10-20 06:34:50.${expected}`);
  }
  assert.equal(formatDateTime("2026-10-20T06:34:50Z", FORMAT, "UTC"), "2026-10-20 06:34:50.0000000");
});

test("timezone conversion changes the wall clock but preserves sub-millisecond evidence", async () => {
  const { formatDateTime } = await load();
  assert.equal(formatDateTime("2026-12-31T23:59:59.9999999Z", FORMAT, "Asia/Tokyo"),
    "2027-01-01 08:59:59.9999999");
  assert.equal(formatDateTime("2026-10-20T15:34:50.1234567+09:00", FORMAT, "UTC"),
    "2026-10-20 06:34:50.1234567");
  assert.equal(formatDateTime("2026-10-20T06:34:50.0000001Z", FORMAT, "America/New_York"),
    "2026-10-20 02:34:50.0000001");
  const localRaw = "2026-10-20T06:34:50.1234567Z";
  assert.ok(formatDateTime(localRaw, FORMAT, "local").endsWith(".1234567"));
});

test("naive and US timestamps retain their original fractions", async () => {
  const { formatDateTime } = await load();
  for (const [raw, options] of [
    ["2026-10-20 06:34:50.1234567"],
    ["2026-10-20 06:34:50.1234567 +00:00"],
    ["2026-10-20t06:34:50.1234567z"],
    ["10-20-2026 03:34:50.1234567 PM +09:00"],
    ["10-20-2026 15:34:50.1234567 +09:00"],
  ]) {
    const day = raw.startsWith("03-08") ? "2026-08-03" : "2026-10-20";
    assert.equal(formatDateTime(raw, FORMAT, "UTC", options), `${day} 06:34:50.1234567`, raw);
  }
});

test("main process and renderer extract identical textual fractions without inventing precision", async () => {
  const backend = require("../electron/utils/forensic-normalize");
  const renderer = await import("../src/utils/forensic-normalize.js");
  for (const [value, expected] of [
    ["2026-10-20T06:34:50.0000001Z", "0000001"],
    ["2026-10-20t06:34:50.1234567z", "1234567"],
    ["20-10-2026 15:34:50,1234567 +09:00", "1234567"],
    ["2026-10-20T06:34:50Z", ""],
    ["1720000000.1234567", ""],
    ["45200.1234567", ""],
    [1720000000123, ""],
    [null, ""],
  ]) {
    assert.equal(backend.timestampFraction(value), expected);
    assert.equal(renderer.timestampFraction(value), expected);
  }
});

test("legacy formats, numeric epochs, missing and invalid values retain their behavior", async () => {
  const { formatDateTime, UNSET_TIMESTAMP_LABEL } = await load();
  assert.equal(formatDateTime("2026-10-20T06:34:50.1234567Z", "dd/MM/yyyy HH:mm:ss", "UTC"),
    "20/10/2026 06:34:50");
  const ms = Date.UTC(2026, 9, 20, 6, 34, 50, 123);
  for (const value of [ms, String(ms)]) {
    assert.equal(formatDateTime(value, FORMAT, "UTC"), "2026-10-20 06:34:50.1230000");
  }
  assert.equal(formatDateTime("", FORMAT, "UTC"), "");
  assert.equal(formatDateTime(null, FORMAT, "UTC"), "");
  assert.equal(formatDateTime("invalid", FORMAT, "UTC"), "invalid");
  assert.equal(formatDateTime("1601-01-01T00:00:00.0000000Z", FORMAT, "UTC"), UNSET_TIMESTAMP_LABEL);
});

test("zoned sort keys keep events distinguishable within a single millisecond", () => {
  const fns = {};
  require("../electron/db/runtime-functions").registerRuntimeFunctions({
    function: (name, options, fn) => { fns[name] = fn; },
  });
  const cases = [
    ["2026-10-20T06:34:50.1234567Z", "2026-10-20 06:34:50.1234567"],
    ["2026-10-20T15:34:50.0000001+09:00", "2026-10-20 06:34:50.0000001"],
    ["2026-10-20T06:34:50.999999999Z", "2026-10-20 06:34:50.999999999"],
    ["10-20-2026 03:34:50.1234567 PM +09:00", "2026-10-20 06:34:50.1234567"],
  ];
  for (const [raw, expected] of cases) assert.equal(fns.sort_datetime(raw), expected);
  const later = "2026-10-20T06:34:50.1234568Z";
  const earlier = "2026-10-20T06:34:50.1234567Z";
  assert.ok(fns.sort_datetime(earlier) < fns.sort_datetime(later));
});

test("slash and month-name dates keep the displayed fraction in their sort keys", async () => {
  const { formatDateTime } = await load();
  const fns = {};
  require("../electron/db/runtime-functions").registerRuntimeFunctions({
    function: (name, options, fn) => { fns[name] = fn; },
  });
  for (const [raw, expected] of [
    ["2026/10/20 06:34:50.1234567", "2026-10-20 06:34:50.1234567"],
    ["Oct 20 2026 06:34:50.0000001", "2026-10-20 06:34:50.0000001"],
    ["2026/12/31 23:59:59.9999999", "2026-12-31 23:59:59.9999999"],
    ["Oct 20 2026 15:34:50.1234567 GMT+0900", "2026-10-20 06:34:50.1234567"],
    ["2026/10/20 06:34:50.5", "2026-10-20 06:34:50.500"],
    ["Oct 20 2026 06:34:50", "2026-10-20 06:34:50.000"],
  ]) {
    assert.equal(fns.sort_datetime(raw), expected, `sort: ${raw}`);
    const [sec, fraction] = expected.split(".");
    assert.equal(formatDateTime(raw, FORMAT, "UTC"), `${sec}.${fraction.padEnd(7, "0")}`, `display: ${raw}`);
  }
  assert.ok(fns.sort_datetime("2026/10/20 06:34:50.1230001") < fns.sort_datetime("2026/10/20 06:34:50.1234567"));
  assert.ok(fns.sort_datetime("Oct 20 2026 06:34:50.1239999") < fns.sort_datetime("Oct 20 2026 06:34:50.124"));
});

test("Hayabusa CSV import keeps source precision through display, sorting and date filters", async (t) => {
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const TimelineDB = require("../electron/db");
  const { parseCSVStream } = require("../electron/parsers/csv");
  const { formatDateTime } = await load();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-precision-"));
  const db = new TimelineDB();
  t.after(() => { db.closeAll(); fs.rmSync(dir, { recursive: true, force: true }); });
  const file = path.join(dir, "hayabusa.csv");
  const fractions = ["9999999", "1234568", "1234567", "0000001"];
  fs.writeFileSync(file, "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details,RuleFile,RuleID\n"
    + fractions.map((f, i) => `2026-10-20T06:34:50.${f}Z,Example,high,HOST,Sysmon,1,${i + 1},example,example.yml,example`).join("\n") + "\n");
  db._dbPathHint = path.join(dir, "timeline.db");
  await parseCSVStream(file, "precision", db, () => {});
  const expected = [...fractions].sort().map((f) => `2026-10-20T06:34:50.${f}Z`);
  const check = () => {
    const result = db.queryRows("precision", { offset: 0, limit: 10, sortCol: "Timestamp", sortDir: "asc" });
    assert.deepEqual(result.rows.map((r) => r.Timestamp), expected, "raw imported timestamps stay unchanged");
    assert.deepEqual(result.rows.map((r) => formatDateTime(r.Timestamp, FORMAT, "UTC")),
      expected.map((s) => s.replace("T", " ").replace("Z", "")));
    const filtered = db.queryRows("precision", {
      offset: 0, limit: 10,
      dateRangeFilters: { Timestamp: {
        from: "2026-10-20T06:34:50.1234568Z", to: "2026-10-20T06:34:50.1234568Z",
      } },
    });
    assert.deepEqual(filtered.rows.map((r) => r.Timestamp), ["2026-10-20T06:34:50.1234568Z"]);
  };
  check();
  await db.buildIndexesAsync("precision");
  check(); // Also exercise the persisted keys used after background indexing.
});

test("renderer and main process agree on offset whitespace and fractional numeric dates", async () => {
  const backend = require("../electron/utils/forensic-normalize");
  const renderer = await import("../src/utils/forensic-normalize.js");
  const expected = Date.UTC(2026, 9, 20, 6, 34, 50, 123);
  for (const raw of [
    "2026-10-20 06:34:50.1234567 +00:00",
    "2026-10-20 15:34:50.1234567 +09:00",
    "2026-10-20 05:34:50.1234567 -01:00",
    "10-20-2026 03:34:50.1234567 PM +09:00",
    "10/20/2026 06:34:50.1234567",
  ]) {
    assert.equal(backend.normalizeTimestamp(raw), expected, raw);
    assert.equal(renderer.normalizeTimestamp(raw), expected, raw);
  }
});
