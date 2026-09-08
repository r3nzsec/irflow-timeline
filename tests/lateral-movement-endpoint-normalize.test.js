const test = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeHostEndpoint,
  isExcludedEndpoint,
  hostsAreSameMachine,
  buildObservedHostAliases,
} = require("../electron/analyzers/lateral-movement/endpoint-normalize");

test("normalizes address:port and bracketed IPv6 host values", () => {
  assert.equal(normalizeHostEndpoint("10.2.10.113:3389"), "10.2.10.113");
  assert.equal(normalizeHostEndpoint("[2001:db8::4]:3389"), "2001:DB8::4");
  assert.equal(normalizeHostEndpoint("wks01.example.test."), "WKS01.EXAMPLE.TEST");
});

test("rejects loopback and collector placeholder endpoints", () => {
  for (const value of ["127.0.0.1:0", "::1:0", "[::1]:3389", "-:-", "(empty)", "LOCALHOST", "::ffff:127.0.0.1"]) {
    assert.equal(isExcludedEndpoint(value), true, `${value} should be excluded`);
  }
  assert.equal(isExcludedEndpoint("10.2.10.113:3389"), false);
});

test("folds IPv4-mapped IPv6 to the IPv4 form", () => {
  assert.equal(normalizeHostEndpoint("::ffff:10.1.1.5"), "10.1.1.5");
  assert.equal(normalizeHostEndpoint("::FFFF:10.1.1.5:3389"), "10.1.1.5");
});

test("hostsAreSameMachine equates NetBIOS and FQDN of the same box", () => {
  assert.equal(hostsAreSameMachine("WKS01", "WKS01.corp.local"), true);
  assert.equal(hostsAreSameMachine("WKS01.corp.local", "WKS01"), true);
  assert.equal(hostsAreSameMachine("WKS01", "WKS02"), false);
  assert.equal(hostsAreSameMachine("10.1.1.5", "WKS01"), false);
});

test("aliases one observed FQDN to its observed short name without cross-domain collisions", () => {
  const safe = buildObservedHostAliases(["WKS2390", "WKS2390.ORIONHUBS.LOCAL", "DC01"]);
  assert.equal(safe.get("WKS2390.ORIONHUBS.LOCAL"), "WKS2390");

  const ambiguous = buildObservedHostAliases([
    "WKS2390",
    "WKS2390.NORTH.EXAMPLE",
    "WKS2390.SOUTH.EXAMPLE",
  ]);
  assert.equal(ambiguous.has("WKS2390.NORTH.EXAMPLE"), false);
  assert.equal(ambiguous.has("WKS2390.SOUTH.EXAMPLE"), false);
});
