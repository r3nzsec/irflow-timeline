// Unit tests for the canonical forensic normalizers.
// Run with: npm test  (or `node --test tests/forensic-normalize.test.js`)
//
// Both backend (CJS) and renderer (ESM) copies must produce identical output for
// every input — they share the burden of fix #2/#3/#4. The renderer copy is read
// via fs and eval'd into a sandbox so this single test file covers both.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const backend = require("../electron/utils/forensic-normalize");

// Load the ESM mirror by stripping `export` keywords and exec'ing in a vm sandbox.
// This avoids needing a build step or experimental loader flags.
function loadRendererMirror() {
  const src = fs.readFileSync(path.join(__dirname, "..", "src", "utils", "forensic-normalize.js"), "utf8");
  const munged = src.replace(/^export\s+function\s+/gm, "function ");
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(
    munged + "\n;Object.assign(globalThis, { normalizeTimestamp, isUnsetWindowsTimestamp, compareTimestamps, normalizeGuid, normalizePid, normalizeLogonId, normalizeHost, normalizeUser });",
    ctx,
  );
  return {
    normalizeTimestamp: ctx.normalizeTimestamp,
    isUnsetWindowsTimestamp: ctx.isUnsetWindowsTimestamp,
    compareTimestamps: ctx.compareTimestamps,
    normalizeGuid: ctx.normalizeGuid,
    normalizePid: ctx.normalizePid,
    normalizeLogonId: ctx.normalizeLogonId,
    normalizeHost: ctx.normalizeHost,
    normalizeUser: ctx.normalizeUser,
  };
}
const renderer = loadRendererMirror();

// Pair every assertion to run against both copies — drift is the bug we're guarding.
function bothEq(name, fn, expected) {
  test(`backend/renderer parity: ${name}`, () => {
    const a = fn(backend);
    const b = fn(renderer);
    assert.deepEqual(a, expected, `backend produced ${a}, expected ${expected}`);
    assert.deepEqual(b, expected, `renderer produced ${b}, expected ${expected}`);
  });
}

// ---------- normalizeTimestamp ----------

bothEq("ISO with Z",       (m) => m.normalizeTimestamp("2026-03-15T12:00:00Z"), Date.UTC(2026, 2, 15, 12, 0, 0));
bothEq("ISO space sep",    (m) => m.normalizeTimestamp("2026-03-15 12:00:00"),  Date.UTC(2026, 2, 15, 12, 0, 0));
bothEq("ISO date only",    (m) => m.normalizeTimestamp("2026-03-15"),           Date.UTC(2026, 2, 15, 0, 0, 0));
bothEq("US date noon PM",  (m) => m.normalizeTimestamp("3/15/2026 12:30:00 PM"), Date.UTC(2026, 2, 15, 12, 30, 0));
bothEq("US date midnight AM", (m) => m.normalizeTimestamp("3/15/2026 12:00:00 AM"), Date.UTC(2026, 2, 15, 0, 0, 0));
bothEq("US date 2pm",      (m) => m.normalizeTimestamp("3/15/2026 2:00:00 PM"),  Date.UTC(2026, 2, 15, 14, 0, 0));
bothEq("Unix seconds",     (m) => m.normalizeTimestamp("1773360000"),            1773360000 * 1000);
bothEq("Unix millis",      (m) => m.normalizeTimestamp("1773360000123"),         1773360000123);
bothEq("empty → NaN",      (m) => Number.isNaN(m.normalizeTimestamp("")),        true);
bothEq("null → NaN",       (m) => Number.isNaN(m.normalizeTimestamp(null)),      true);
bothEq("garbage → NaN",    (m) => Number.isNaN(m.normalizeTimestamp("nope")),    true);
bothEq("FILETIME epoch is unset", (m) => m.isUnsetWindowsTimestamp("1601-01-01 00:00:00"), true);
bothEq("FILETIME epoch Z is unset", (m) => m.isUnsetWindowsTimestamp("1601-01-01T00:00:00.0000000Z"), true);
bothEq("real TimeCreated is not unset", (m) => m.isUnsetWindowsTimestamp("2025-04-02 02:37:03"), false);
bothEq("FILETIME epoch → NaN", (m) => Number.isNaN(m.normalizeTimestamp("1601-01-01 00:00:00")), true);

// ---------- compareTimestamps ----------

test("compareTimestamps orders ISO and US-date in same chronology", () => {
  const a = "2026-03-15T10:00:00Z";
  const b = "3/15/2026 11:00:00 AM";
  assert.ok(backend.compareTimestamps(a, b) < 0);
  assert.ok(renderer.compareTimestamps(a, b) < 0);
});

test("compareTimestamps puts unparseable values last", () => {
  assert.ok(backend.compareTimestamps("2026-03-15T10:00:00Z", "garbage") < 0);
  assert.ok(renderer.compareTimestamps("garbage", "2026-03-15T10:00:00Z") > 0);
});

// ---------- normalizeGuid ----------

bothEq("brace-wrapped GUID matches plain",
  (m) => m.normalizeGuid("{7BF9956E-0A95-6931-A700-000000000700}"),
  "7bf9956e-0a95-6931-a700-000000000700");
bothEq("plain GUID stays lowercase",
  (m) => m.normalizeGuid("7bf9956e-0a95-6931-a700-000000000700"),
  "7bf9956e-0a95-6931-a700-000000000700");
bothEq("uppercase GUID lowered",
  (m) => m.normalizeGuid("7BF9956E-0A95-6931-A700-000000000700"),
  "7bf9956e-0a95-6931-a700-000000000700");
bothEq("null guid → empty", (m) => m.normalizeGuid(null), "");

test("brace and plain GUID compare equal after normalize (Finding #3)", () => {
  const sysmon = "{7BF9956E-0A95-6931-A700-000000000700}";
  const security = "7bf9956e-0a95-6931-a700-000000000700";
  assert.equal(backend.normalizeGuid(sysmon), backend.normalizeGuid(security));
  assert.equal(renderer.normalizeGuid(sysmon), renderer.normalizeGuid(security));
});

// ---------- normalizePid ----------

bothEq("decimal PID",         (m) => m.normalizePid("1234"),  "1234");
bothEq("hex PID 0x1a2c",      (m) => m.normalizePid("0x1a2c"), String(0x1a2c));
bothEq("hex PID 0X1A2C",      (m) => m.normalizePid("0X1A2C"), String(0x1a2c));
bothEq("padded PID",          (m) => m.normalizePid(" 5668 "), "5668");
bothEq("empty PID → empty",   (m) => m.normalizePid(""),       "");

// ---------- normalizeLogonId ----------

bothEq("hex logon id 0x3e7", (m) => m.normalizeLogonId("0x3e7"), "999");
bothEq("decimal logon id",    (m) => m.normalizeLogonId("999"),  "999");

test("hex and decimal logon IDs equal after normalize (Finding #3)", () => {
  assert.equal(backend.normalizeLogonId("0x3e7"), backend.normalizeLogonId("999"));
  assert.equal(renderer.normalizeLogonId("0x3e7"), renderer.normalizeLogonId("999"));
});

// ---------- normalizeHost ----------

bothEq("plain host upper",      (m) => m.normalizeHost("host01"),    "HOST01");
bothEq("UNC prefix stripped",   (m) => m.normalizeHost("\\\\HOST01"), "HOST01");
bothEq("trim + upper",          (m) => m.normalizeHost("  Host01 "), "HOST01");
bothEq("empty host stays empty",(m) => m.normalizeHost(""),           "");

// ---------- normalizeUser ----------

bothEq("DOMAIN\\\\user → user",  (m) => m.normalizeUser("CORP\\Alice"), "alice");
bothEq("plain user lowered",    (m) => m.normalizeUser("Alice"),       "alice");
bothEq("trim",                  (m) => m.normalizeUser("  alice "),    "alice");
