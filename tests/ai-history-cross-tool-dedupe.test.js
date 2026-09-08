"use strict";

// Cross-tool correlation annotates matching bodies while preserving every source occurrence.

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { dedupeCrossToolPrompts } = require("../electron/parsers/ai-history/row-utils");

const PREFIX = "please review the following module and fix any bug you can find in the handler".padEnd(125, ".");

const row = (tool, tail, ts) => ({
  Role: "user", Tool: tool, Summary: PREFIX + tail, FullText: PREFIX + tail,
  Timestamp: ts || "2024-01-01 00:00:00", SessionId: "s1", AlsoInTools: "",
});

test("same tool + shared 120-char prefix but different bodies are kept (no silent drop)", () => {
  const out = dedupeCrossToolPrompts([row("Claude Code", " alpha", "2024-01-01 00:00:00"),
    row("Claude Code", " beta", "2024-06-01 00:00:00")]);
  assert.equal(out.length, 2, "distinct same-tool prompts survive");
});

test("same prompt across different tools keeps both source occurrences with correlation provenance", () => {
  const out = dedupeCrossToolPrompts([row("Claude Code", " identical body"), row("Cursor", " identical body")]);
  assert.equal(out.length, 2);
  assert.ok(out.every((item) => item.AlsoInTools === "Claude Code, Cursor"));
});

test("shared prefixes with different bodies are not correlated", () => {
  const out = dedupeCrossToolPrompts([row("Claude Code", " alpha"), row("Cursor", " beta")]);
  assert.equal(out.length, 2);
  assert.ok(out.every((item) => item.AlsoInTools === ""));
});

test("rows without a cross-tool key (short/non-user) pass through untouched", () => {
  const short = { Role: "user", Tool: "Cursor", Summary: "hi", FullText: "hi", Timestamp: "2024-01-01 00:00:00" };
  const out = dedupeCrossToolPrompts([short, short]);
  assert.equal(out.length, 2);
});
