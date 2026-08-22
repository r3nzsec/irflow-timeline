const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildScanCommand,
  createScanOutputPaths,
  hayabusaMajorVersion,
} = require("../electron/analyzers/sigma/evtx-scanner/command-builder");
const { normalizeLevel } = require("../electron/analyzers/sigma/evtx-scanner/output-parser");

const OUT = { actualOutput: "/tmp/out.csv", tmpHtmlReport: "/tmp/report.html" };

function build(options, outputPaths = OUT) {
  return buildScanCommand({ dirPath: "/case", options, outputPaths }).args;
}

test("hayabusaMajorVersion parses the leading major from version strings", () => {
  assert.equal(hayabusaMajorVersion("v4.0.0"), 4);
  assert.equal(hayabusaMajorVersion("v3.2.0"), 3);
  assert.equal(hayabusaMajorVersion("2.19.0"), 2);
  assert.equal(hayabusaMajorVersion("Hayabusa v4.1.2"), 4);
  assert.equal(hayabusaMajorVersion("v10.0.0"), 10);
  assert.equal(hayabusaMajorVersion("v4"), 4);
  assert.equal(hayabusaMajorVersion(null), null);
  assert.equal(hayabusaMajorVersion(undefined), null);
  assert.equal(hayabusaMajorVersion(""), null);
});

test("hayabusaMajorVersion ignores stray digits that are not a version", () => {
  // Routing on a loose digit match would send a v4 binary down the legacy v2/v3 CLI,
  // which fails on the first argument parse. Unrecognised input must read as "unknown".
  for (const junk of ["garbage", "unknown-3", "hayabusa", "-", "20260101"]) {
    assert.equal(hayabusaMajorVersion(junk), null, junk);
  }
});

test("the scan output file extension matches the requested output type", () => {
  // json and jsonl both used to land on ".jsonl", so a `-t json` run wrote a JSON
  // document into a file named .jsonl.
  assert.ok(createScanOutputPaths("csv").actualOutput.endsWith(".csv"));
  assert.ok(createScanOutputPaths("json").actualOutput.endsWith(".json"));
  assert.ok(createScanOutputPaths("jsonl").actualOutput.endsWith(".jsonl"));
  assert.ok(createScanOutputPaths().actualOutput.endsWith(".csv"), "defaults to csv");
});

test("abbreviated Hayabusa level names normalize to full severities", () => {
  // v4 emits abbreviated levels; unmapped they become their own buckets and drop out
  // of the severity histogram entirely.
  assert.equal(normalizeLevel("crit"), "critical");
  assert.equal(normalizeLevel("med"), "medium");
  assert.equal(normalizeLevel("info"), "informational");
  assert.equal(normalizeLevel("CRIT"), "critical");
  assert.equal(normalizeLevel("high"), "high");
  assert.equal(normalizeLevel("critical"), "critical");
  assert.equal(normalizeLevel(""), "medium", "empty falls back to medium");
  assert.equal(normalizeLevel(undefined), "medium");
});

test("v4+ uses the unified dfir-timeline subcommand with -t output type", () => {
  const csv = build({ version: "v4.0.0", outputMode: "csv" });
  assert.equal(csv[0], "dfir-timeline");
  assert.equal(csv[csv.indexOf("-t") + 1], "csv");
  assert.ok(!csv.includes("csv-timeline"));
  assert.ok(!csv.includes("--jsonl-output"));

  const jsonl = build({ version: "v4.0.0", outputMode: "jsonl" }, { actualOutput: "/tmp/out.jsonl", tmpHtmlReport: "/tmp/report.html" });
  assert.equal(jsonl[0], "dfir-timeline");
  assert.equal(jsonl[jsonl.indexOf("-t") + 1], "jsonl");
  assert.ok(!jsonl.includes("--jsonl-output"));
});

test("v2/v3 use the legacy csv-timeline/json-timeline subcommands without -t", () => {
  const csv = build({ version: "v3.2.0", outputMode: "csv" });
  assert.equal(csv[0], "csv-timeline");
  assert.ok(!csv.includes("-t"));
  assert.ok(!csv.includes("dfir-timeline"));

  const jsonl = build({ version: "v3.2.0", outputMode: "jsonl" }, { actualOutput: "/tmp/out.jsonl", tmpHtmlReport: "/tmp/report.html" });
  assert.equal(jsonl[0], "json-timeline");
  assert.ok(jsonl.includes("--jsonl-output"));
  assert.ok(!jsonl.includes("-t"));

  // Pre-v4 json (array) mode uses json-timeline with no --jsonl-output flag.
  const json = build({ version: "v2.19.0", outputMode: "json" }, { actualOutput: "/tmp/out.json", tmpHtmlReport: "/tmp/report.html" });
  assert.equal(json[0], "json-timeline");
  assert.ok(!json.includes("--jsonl-output"));
});

test("unknown version defaults to the modern (v4+) CLI shape", () => {
  for (const version of [null, undefined, "garbage"]) {
    const args = build({ version, outputMode: "csv" });
    assert.equal(args[0], "dfir-timeline", `version=${String(version)}`);
    assert.equal(args[args.indexOf("-t") + 1], "csv");
  }
});
