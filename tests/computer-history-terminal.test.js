"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  TERMINAL_VALUE_KIND,
  isTerminalValueChanged,
  extractTerminalBuffer,
  describeTerminalActivity,
  terminalBufferNote,
  windowLooksLikeSsh,
} = require("../electron/parsers/ai-history/computer-history-terminal");
const {
  parseSkysightEvent,
  describeActivity,
  resolveEventClass,
  isScrollbackSnapshot,
} = require("../electron/parsers/ai-history/computer-history");
const { CLASS_TERMINAL } = require("../electron/parsers/ai-history/computer-history-schema");

const SSH_BUFFER = [
  "Last login: Thu Aug 20 12:28:29 on ttys032",
  "dfir@host ~ % ssh root@203.0.113.10",
  "root@203.0.113.10's password: ",
].join("\n");

const TRUNCATED_BUFFER = "[truncated to visible range]            3956 100%   36.29MB/s   00:00:00 (xfer#163746)\n";

test("isTerminalValueChanged is exact on the live kind name", () => {
  assert.equal(isTerminalValueChanged(TERMINAL_VALUE_KIND), true);
  assert.equal(isTerminalValueChanged("keyboard.text_input"), false);
  assert.equal(isTerminalValueChanged(""), false);
});

test("extractTerminalBuffer reads keyboard.target.value and the visible-range prefix", () => {
  const full = extractTerminalBuffer({
    keyboard: { target: { role: "AXTextArea", description: "shell", value: SSH_BUFFER } },
  });
  assert.equal(full.content, SSH_BUFFER);
  assert.equal(full.truncatedVisible, false);
  assert.equal(full.targetRole, "AXTextArea");
  assert.equal(full.targetDescription, "shell");

  const cut = extractTerminalBuffer({
    keyboard: { target: { value: TRUNCATED_BUFFER } },
  });
  assert.equal(cut.truncatedVisible, true);
  assert.ok(cut.content.startsWith("[truncated to visible range]"));
});

test("describeTerminalActivity names SSH + Secure Input without claiming a recovered password", () => {
  assert.equal(
    describeTerminalActivity({
      app: { secureInput: true },
      window: { title: "ssh" },
    }),
    "SSH Session (Secure Input)",
  );
  assert.equal(
    describeTerminalActivity({ app: { secureInput: true }, window: { title: "-zsh" } }),
    "Terminal Buffer (Secure Input)",
  );
  assert.equal(describeTerminalActivity({ window: { title: "Default (ssh)" } }), "SSH Session");
  assert.equal(windowLooksLikeSsh({ window: { title: "Default (ssh)" } }), true);
  assert.equal(windowLooksLikeSsh({ window: { title: "ssh-keygen" } }), false);
  assert.equal(
    describeTerminalActivity({ app: { secureInput: true }, window: { title: "ssh-keygen" } }),
    "Terminal Buffer (Secure Input)",
  );
});

test("parseSkysightEvent strips AX NUL bytes so CSV export stays valid", () => {
  const row = parseSkysightEvent({
    id: 1,
    kind: "terminal.value_changed",
    timestamp: "2026-08-20T15:02:29Z",
    app: { bundleIdentifier: "com.googlecode.iterm2", name: "iTerm2", secureInput: true },
    keyboard: { target: { role: "AXTextArea", value: "dfir@host ~ % ls\nfoo\u0000bar" } },
    window: { title: "ssh-keygen" },
  }, "/e", {}, {}, {});
  assert.equal(row.Content.includes("\u0000"), false);
  assert.equal(row.Content.includes("foobar"), true);
  assert.equal(row.Activity, "Terminal Buffer (Secure Input)");
});

test("parseSkysightEvent keeps the terminal buffer in Content instead of dropping it", () => {
  const row = parseSkysightEvent({
    id: 6787,
    kind: "terminal.value_changed",
    timestamp: "2026-08-20T06:51:11Z",
    app: { bundleIdentifier: "com.googlecode.iterm2", name: "iTerm2", secureInput: true },
    keyboard: { target: { description: "shell", role: "AXTextArea", value: SSH_BUFFER } },
    window: { title: "ssh" },
  }, "/segments/2026-08-20T06-50-00Z/events.jsonl", {}, {}, {});

  assert.ok(row);
  assert.equal(row.EventKind, TERMINAL_VALUE_KIND);
  assert.equal(row.EventClass, CLASS_TERMINAL);
  assert.equal(row.AppClass, CLASS_TERMINAL);
  assert.equal(row.Activity, "SSH Session (Secure Input)");
  assert.equal(row.Content, SSH_BUFFER);
  assert.match(row.Content, /ssh root@203\.0\.113\.10/);
  assert.match(row.Description, /Secure Input was engaged/);
  assert.match(row.Description, /command that opened the prompt is in Content/);
  assert.equal(isScrollbackSnapshot(row), true, "must not be coalesced with keystroke runs");
});

test("parseSkysightEvent records that a truncated AX range is not full scrollback", () => {
  const row = parseSkysightEvent({
    id: 20733,
    kind: "terminal.value_changed",
    timestamp: "2026-08-20T10:45:12Z",
    app: { bundleIdentifier: "com.googlecode.iterm2", name: "iTerm2", secureInput: true },
    keyboard: { target: { description: "shell", role: "AXTextArea", value: TRUNCATED_BUFFER } },
    window: { title: "ssh" },
  }, "/e", {}, {}, {});
  assert.match(row.Description, /VISIBLE terminal range only/);
  assert.ok(terminalBufferNote({
    app: { secureInput: true },
    keyboard: { target: { value: TRUNCATED_BUFFER } },
  }).length >= 2);
});

test("resolveEventClass / describeActivity classify terminal.value_changed as Terminal", () => {
  assert.equal(resolveEventClass("terminal.value_changed", "com.googlecode.iterm2", ""), CLASS_TERMINAL);
  assert.equal(
    describeActivity("terminal.value_changed", { app: { secureInput: false }, window: { title: "iTerm2" } }),
    "Terminal Buffer",
  );
});
