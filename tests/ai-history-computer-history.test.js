"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const {
  findMemoriesGitDir,
  parseLogOutput,
} = require("../electron/parsers/ai-history/skysight-git-recovery");
const {
  decodeUuidV7,
  findIdentityRoot,
  listAccountPlists,
  readChatgptStatsigServicePlist,
} = require("../electron/parsers/ai-history/skysight-identity");

const {
  segmentStampToMs,
  msToSegmentId,
  isSegmentDirName,
  isSkysightSegmentsDir,
  isSkysightResourcesDir,
  isComputerHistoryDir,
  isSkysightEventsFile,
  isSkysightSummaryFile,
  findSegmentsDir,
  findSkysightResourcesDir,
  resolveEventClass,
  resolveAppClass,
  resolveFidelityTier,
  stampFidelityTiers,
  extractSummaryCitations,
  recoverDeletedSummaries,
  collectFeatureState,
  collectIdentityArtifacts,
  parseSkysightEvent,
  coalesceTypedInput,
  isScrollbackSnapshot,
  isTypingContinuation,
  readSegmentMetadata,
  listSegmentDirs,
  detectSegmentGaps,
  parseSummaryFrontmatter,
  describeActivity,
  parseSummaryFile,
  parseSummaryFileRows,
  extractSummarySection,
  collectSkysightDerivedMemory,
  extractSegmentFile,
  extractComputerHistoryDir,
  extractComputerHistoryPath,
  dedupeRows,
} = require("../electron/parsers/ai-history/computer-history");
const {
  COMPUTER_HISTORY_COLUMNS,
  CLASS_SESSION,
  CLASS_WEB,
  CLASS_INPUT,
  CLASS_UI,
  CLASS_DATA_MOVEMENT,
  CLASS_TERMINAL,
  CLASS_COMMUNICATION,
  CLASS_NARRATIVE,
} = require("../electron/parsers/ai-history/computer-history-schema");

const FIXTURE_ROOT = path.join(__dirname, "fixtures/ai-history/computer-history");
const FIXTURE_CONTAINER = path.join(FIXTURE_ROOT, "2DC432GLL2.com.openai.sky.CUAService");
const FIXTURE_SEGMENTS = path.join(
  FIXTURE_CONTAINER, "Library/Caches/ComputerUse/Skysight/segments",
);
const FIXTURE_SEGMENT_1 = path.join(FIXTURE_SEGMENTS, "2026-08-14T05-20-00Z");
const FIXTURE_CODEX = path.join(FIXTURE_ROOT, ".codex");
const FIXTURE_SUMMARY = path.join(
  FIXTURE_CODEX,
  "memories/extensions/skysight/resources/2026-08-14T05-20-00-jChV-10min-memory-summary.md",
);

/* -------------------------------------------------------------- timestamps */

test("segmentStampToMs / msToSegmentId round-trip the bucket naming", () => {
  const ms = segmentStampToMs("2026-08-14T05-20-00Z");
  assert.equal(new Date(ms).toISOString(), "2026-08-14T05:20:00.000Z");
  assert.equal(msToSegmentId(ms), "2026-08-14T05-20-00Z");
  // Summary filenames carry the same stamp without the trailing Z.
  assert.equal(segmentStampToMs("2026-08-14T05-20-00"), ms);
  assert.equal(segmentStampToMs("not-a-stamp"), null);
});

/* ------------------------------------------------------------- recognition */

test("segment and artifact recognisers accept only the real shapes", () => {
  assert.equal(isSegmentDirName("2026-08-14T05-20-00Z"), true);
  assert.equal(isSegmentDirName("2026-08-14T05:20:00Z"), false);
  assert.equal(isSegmentDirName("segments"), false);

  assert.equal(isSkysightSegmentsDir(FIXTURE_SEGMENTS), true);
  assert.equal(isSkysightSegmentsDir(FIXTURE_SEGMENT_1), false);
  assert.equal(isSkysightResourcesDir(path.dirname(FIXTURE_SUMMARY)), true);

  assert.equal(isSkysightEventsFile(path.join(FIXTURE_SEGMENT_1, "events.jsonl")), true);
  assert.equal(isSkysightEventsFile(path.join(FIXTURE_SEGMENT_1, "metadata.json")), false);
  assert.equal(isSkysightSummaryFile(FIXTURE_SUMMARY), true);
  assert.equal(isSkysightSummaryFile("notes.md"), false);
});

test("findSegmentsDir resolves from container, bucket, events file and triage root", () => {
  assert.equal(findSegmentsDir(FIXTURE_SEGMENTS), FIXTURE_SEGMENTS);
  assert.equal(findSegmentsDir(FIXTURE_CONTAINER), FIXTURE_SEGMENTS);
  assert.equal(findSegmentsDir(FIXTURE_SEGMENT_1), FIXTURE_SEGMENTS);
  assert.equal(findSegmentsDir(path.join(FIXTURE_SEGMENT_1, "events.jsonl")), FIXTURE_SEGMENTS);
  // A KAPE/triage-style root above the container still resolves, scoped inside itself.
  assert.equal(findSegmentsDir(FIXTURE_ROOT), FIXTURE_SEGMENTS);
  assert.equal(findSegmentsDir(FIXTURE_CODEX), null);
});

test("findSkysightResourcesDir resolves from .codex root and summary file", () => {
  const resources = path.dirname(FIXTURE_SUMMARY);
  assert.equal(findSkysightResourcesDir(FIXTURE_CODEX), resources);
  assert.equal(findSkysightResourcesDir(FIXTURE_SUMMARY), resources);
  assert.equal(findSkysightResourcesDir(resources), resources);
});

test("isComputerHistoryDir is true for either artifact family", () => {
  assert.equal(isComputerHistoryDir(FIXTURE_CONTAINER), true);
  assert.equal(isComputerHistoryDir(FIXTURE_CODEX), true);
  assert.equal(isComputerHistoryDir(os.tmpdir()), false);
});

/* ---------------------------------------------------------- classification */

test("resolveEventClass keeps cross-app drag as DataMovement despite app override", () => {
  // Terminal override must not mask the highest-signal class.
  assert.equal(resolveEventClass("mouse.drag", "com.googlecode.iterm2", ""), CLASS_DATA_MOVEMENT);
  assert.equal(resolveEventClass("mouse.drag", "com.openai.codex", ""), CLASS_DATA_MOVEMENT);
});

test("resolveEventClass applies app-family overrides to focus rows only", () => {
  // A focus row's whole meaning is "the user moved to this app", so there the app family IS the class.
  assert.equal(resolveEventClass("window.changed", "com.googlecode.iterm2", ""), CLASS_TERMINAL);
  assert.equal(resolveEventClass("window.changed", "com.microsoft.edgemac", "https://x.test/"), CLASS_WEB);
  assert.equal(resolveEventClass("window.changed", "com.apple.loginwindow", ""), CLASS_SESSION);
  assert.equal(resolveEventClass("keyboard.text_input", "com.openai.codex", ""), CLASS_INPUT);
  assert.equal(resolveEventClass("mouse.click", "com.openai.codex", ""), CLASS_UI);
});

test("app family never reclassifies a non-focus event away from what the user did", () => {
  // Regression: folding the bundle into every kind reclassified 801 of ~930 Input events, so
  // filtering EventClass = Input missed all typing in exactly the apps that matter most.
  assert.equal(resolveEventClass("keyboard.text_input", "ru.keepcoder.Telegram", ""), CLASS_INPUT);
  assert.equal(resolveEventClass("keyboard.shortcut", "com.googlecode.iterm2", ""), CLASS_INPUT);
  assert.equal(resolveEventClass("keyboard.submit", "net.whatsapp.WhatsApp", ""), CLASS_INPUT);
  assert.equal(resolveEventClass("mouse.click", "com.tinyspeck.slackmacgap", ""), CLASS_UI);
  assert.equal(resolveEventClass("selection.changed", "com.googlecode.iterm2", ""), CLASS_DATA_MOVEMENT);
});

test("stampFidelityTiers gives an app one tier instead of one per row", () => {
  // The defect: 43% of events carry no ax object and diffs are short by construction, so per-row
  // tiering made the same app read as "deep content" and "metadata only" on adjacent rows.
  const rows = [
    { BundleId: "com.github.Electron", FidelityTier: "", Description: "" }, // no ax on this event
    { BundleId: "com.github.Electron", FidelityTier: "", Description: "" }, // a short diff
    { BundleId: "com.github.Electron", FidelityTier: "", Description: "" }, // the full tree
    { BundleId: "com.quiet.app", FidelityTier: "", Description: "" },
  ];
  stampFidelityTiers(rows, new Map([["com.github.Electron", 41717], ["com.quiet.app", 120]]));
  assert.deepEqual(rows.map((r) => r.FidelityTier), ["1", "1", "1", "3"]);

  // A provisional tier stamped from the table at parse time is NOT authoritative: by finalization
  // the whole capture has been seen, and evidence of a deeper capture must be able to correct it.
  // Slack shipped pinned to Tier 3 on category reasoning while exposing 53,590 chars of channel
  // content, which produced exactly the wrong "only one side of the conversation" report line.
  const stale = [{ BundleId: "com.tinyspeck.slackmacgap", FidelityTier: "3", Description: "" }];
  stampFidelityTiers(stale, new Map([["com.tinyspeck.slackmacgap", 53590]]));
  assert.equal(stale[0].FidelityTier, "1", "evidence of a deep capture overrides a stale table tier");

  // ...but a thin sample can never argue capability away. Telegram genuinely maxes out around 144
  // chars, so nothing promotes it; a briefly-used browser must not be demoted on low volume.
  const thin = [{ BundleId: "com.google.Chrome", FidelityTier: "1", Description: "" }];
  stampFidelityTiers(thin, new Map([["com.google.Chrome", 6814]]));
  assert.equal(thin[0].FidelityTier, "1", "a short sample never demotes a known-deep app");
});

test("only full-tree captures feed the fidelity profile", () => {
  const axProfile = new Map();
  const opts = { axProfile };
  const ev = (mode, len) => ({
    id: 1, kind: "mouse.click", timestamp: "2026-08-14T05:20:00Z",
    app: { bundleIdentifier: "com.unlisted.app", name: "Unlisted" },
    ax: { mode, text: "x".repeat(len) },
  });
  parseSkysightEvent(ev("diffFromPrevious", 50000), "/e", {}, {}, opts);
  assert.equal(axProfile.get("com.unlisted.app"), undefined, "a diff says nothing about depth");
  parseSkysightEvent(ev("fullTree", 3000), "/e", {}, {}, opts);
  parseSkysightEvent(ev("fullTree", 900), "/e", {}, {}, opts);
  assert.equal(axProfile.get("com.unlisted.app"), 3000, "the largest full capture wins");
});

test("resolveAppClass carries the app family independently of the action", () => {
  assert.equal(resolveAppClass("com.googlecode.iterm2", ""), CLASS_TERMINAL);
  assert.equal(resolveAppClass("ru.keepcoder.Telegram", ""), CLASS_COMMUNICATION);
  assert.equal(resolveAppClass("com.unknown.app", "https://x.test/"), CLASS_WEB);
  assert.equal(resolveAppClass("com.unknown.app", ""), "");
});

test("resolveFidelityTier takes the more capable of table and measurement", () => {
  // No observation: the table is all there is.
  assert.equal(resolveFidelityTier("com.googlecode.iterm2", 0), 1);
  assert.equal(resolveFidelityTier("com.unknown.app", 0), 3, "unknown and unobserved is not 'deep'");

  // Measurement promotes a stale table entry — the Slack case.
  assert.equal(resolveFidelityTier("ru.keepcoder.Telegram", 999999), 1, "evidence beats a stale tier");

  // Measurement never demotes a known-deep app that was simply on screen briefly.
  assert.equal(resolveFidelityTier("com.google.Chrome", 6814), 1, "thin sample does not demote");
  assert.equal(resolveFidelityTier("com.apple.mail", 10), 2, "table floors the tier at its prior");

  // Unknown bundles are tiered purely from what they produced.
  assert.equal(resolveFidelityTier("com.unknown.app", 50000), 1);
  assert.equal(resolveFidelityTier("com.unknown.app", 5000), 2);
  assert.equal(resolveFidelityTier("com.unknown.app", 10), 3);
});

/* ------------------------------------------------------------ event parsing */

test("parseSkysightEvent maps a cross-app drag to origin and destination", () => {
  const row = parseSkysightEvent({
    id: 6,
    kind: "mouse.drag",
    timestamp: "2026-08-14T05:28:22Z",
    mouse: {
      origin: {
        app: { bundleIdentifier: "com.microsoft.edgemac", name: "Microsoft Edge" },
        element: { role: "AXStaticText", value: "a sentence" },
        window: { title: "Example Doc", url: "https://example.test/docs/page" },
      },
      destination: {
        app: { bundleIdentifier: "ru.keepcoder.Telegram", name: "Telegram" },
        element: { role: "AXTextArea" },
        window: { title: "Telegram @ RC" },
      },
    },
  }, "/evidence/events.jsonl", {}, {}, {});

  assert.equal(row.EventClass, CLASS_DATA_MOVEMENT);
  assert.equal(row.Activity, "Cross-App Drag");
  assert.equal(row.Timestamp, "2026-08-14 05:28:22");
  assert.equal(row.BundleId, "com.microsoft.edgemac");
  assert.equal(row.Url, "https://example.test/docs/page");
  assert.equal(row.DestBundleId, "ru.keepcoder.Telegram");
  assert.equal(row.DestWindowTitle, "Telegram @ RC");
  assert.equal(row.Content, "a sentence");
  assert.equal(row.EventId, "6");
});

test("parseSkysightEvent prefers cumulative target.value over the keystroke fragment", () => {
  const row = parseSkysightEvent({
    id: 8,
    kind: "keyboard.text_input",
    timestamp: "2026-08-14T05:28:44Z",
    app: { bundleIdentifier: "com.openai.codex", name: "ChatGPT" },
    keyboard: { target: { role: "AXTextArea", description: "Do anything", value: "What I was working on" }, text: "I was working on" },
    window: { title: "ChatGPT", url: "app://-/index.html" },
  }, "/evidence/events.jsonl", {}, {}, {});

  assert.equal(row.Content, "What I was working on");
  assert.equal(row.ContentLength, "21");
  assert.equal(row.TargetRole, "AXTextArea");
  assert.equal(row.TargetLabel, "Do anything");
});

test("parseSkysightEvent records the key chord and selection offsets", () => {
  const shortcut = parseSkysightEvent({
    id: 13, kind: "keyboard.shortcut", timestamp: "2026-08-14T05:29:59Z",
    app: { bundleIdentifier: "com.googlecode.iterm2", name: "iTerm2" },
    keyboard: { keyEquivalent: "c", modifiers: ["control"], target: { role: "AXTextArea", value: "scrollback" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(shortcut.KeyChord, "control+c");
  assert.equal(shortcut.EventClass, CLASS_INPUT, "the action is typing, wherever it happened");
  assert.equal(shortcut.AppClass, CLASS_TERMINAL, "the app family travels separately");

  const selection = parseSkysightEvent({
    id: 5, kind: "selection.changed", timestamp: "2026-08-14T05:28:20Z",
    app: { bundleIdentifier: "com.microsoft.edgemac", name: "Microsoft Edge" },
    selection: { selectedText: "highlighted", selectedRange: { location: 4963, length: 11 } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(selection.SelectionOffset, "4963");
  assert.equal(selection.SelectionLength, "11");
});

test("parseSkysightEvent drops records without a usable timestamp rather than inventing one", () => {
  assert.equal(parseSkysightEvent({ id: 1, kind: "mouse.click" }, "/e", {}, {}, {}), null);
  assert.equal(parseSkysightEvent({ id: 1, timestamp: "2026-08-14T05:00:00Z" }, "/e", {}, {}, {}), null);
  assert.equal(parseSkysightEvent(null, "/e", {}, {}, {}), null);
});

test("ScreenText is capped but AxLength reports the true on-disk size", () => {
  const big = "x".repeat(5000);
  const row = parseSkysightEvent({
    id: 2, kind: "window.changed", timestamp: "2026-08-14T05:26:56Z",
    app: { bundleIdentifier: "com.openai.codex", name: "ChatGPT" },
    ax: { mode: "fullTree", text: big }, window: { title: "ChatGPT" },
  }, "/evidence/events.jsonl", {}, {}, { screenTextMaxChars: 100 });

  assert.equal(row.AxLength, "5000");
  assert.ok(row.ScreenText.length < 500);
  assert.match(row.ScreenText, /truncated 4900 chars/);

  const omitted = parseSkysightEvent({
    id: 2, kind: "window.changed", timestamp: "2026-08-14T05:26:56Z",
    app: { bundleIdentifier: "com.openai.codex", name: "ChatGPT" },
    ax: { mode: "fullTree", text: big }, window: { title: "ChatGPT" },
  }, "/evidence/events.jsonl", {}, {}, { includeScreenText: false });
  assert.equal(omitted.ScreenText, "");
  assert.equal(omitted.AxLength, "5000");
});

test("a diff capture is qualified on the row, not just in AxMode", () => {
  // 58% of ax-bearing events observed live are diffs. Read as a screen snapshot they understate
  // what was on screen, so the qualification has to survive CSV export.
  const diff = parseSkysightEvent({
    id: 3, kind: "mouse.click", timestamp: "2026-08-14T05:27:10Z",
    app: { bundleIdentifier: "com.microsoft.edgemac", name: "Microsoft Edge" },
    ax: { mode: "diffFromPrevious", text: "only what changed" },
    mouse: { button: "left", target: { role: "AXButton" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(diff.AxMode, "diffFromPrevious");
  assert.match(diff.Description, /CHANGES ONLY/);
  assert.match(diff.Description, /not a full screen capture/);

  const full = parseSkysightEvent({
    id: 4, kind: "window.changed", timestamp: "2026-08-14T05:27:11Z",
    app: { bundleIdentifier: "com.microsoft.edgemac", name: "Microsoft Edge" },
    ax: { mode: "fullTree", text: "the whole visible tree" }, window: { title: "Edge" },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.doesNotMatch(full.Description, /CHANGES ONLY/, "a snapshot needs no qualifier");
});

test("a secure text field is credential entry — a timing anchor, not a recovered password", () => {
  // Secure Input Mode blocks the recorder's event tap, so BOTH the field value and the keystrokes
  // are withheld. Measured live: zero text-bearing input events under secure input across 5,370
  // events. The fixture mirrors that — no `value`, no `text` — because a fixture carrying a
  // readable password would enshrine the exact claim this row must never make.
  const row = parseSkysightEvent({
    id: 9, kind: "keyboard.text_input", timestamp: "2026-08-14T05:33:00Z",
    app: { bundleIdentifier: "in.sinew.Enpass-Desktop", name: "Enpass" },
    keyboard: {
      target: { role: "AXTextField", subrole: "AXSecureTextField", title: "Master password" },
    },
  }, "/evidence/events.jsonl", {}, {}, {});

  assert.equal(row.TargetSubrole, "AXSecureTextField");
  assert.equal(row.Activity, "Credential Entry");
  assert.equal(row.Content, "", "no credential material reaches the row");
  assert.match(row.Description, /SECURE INPUT/);
  assert.match(row.Description, /suppressed the keystrokes/);
  assert.match(row.Description, /not what it was/);

  const submit = parseSkysightEvent({
    id: 10, kind: "keyboard.submit", timestamp: "2026-08-14T05:33:01Z",
    app: { bundleIdentifier: "in.sinew.Enpass-Desktop", name: "Enpass" },
    keyboard: { target: { role: "AXTextField", subrole: "AXSecureTextField" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(submit.Activity, "Credential Submit");

  // app.secureInput is the BROADER signal — system-wide Secure Input Mode, which fires on prompts
  // exposing no secure-field subrole at all. Observed live on a third-party app-lock dialog whose
  // only trace was the focus change, and on 5 events against the subrole's 2.
  const noSubrole = parseSkysightEvent({
    id: 11, kind: "window.changed", timestamp: "2026-08-14T05:33:02Z",
    app: { bundleIdentifier: "com.cisdem.appencrypt", name: "AppCrypt", secureInput: true },
    window: { title: "Please Enter your Password" },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(noSubrole.TargetSubrole, "", "no secure-field subrole on this event at all");
  assert.equal(noSubrole.Activity, "Password Prompt");
  assert.match(noSubrole.Description, /SECURE INPUT/);

  const typedUnderSecureInput = parseSkysightEvent({
    id: 12, kind: "keyboard.text_input", timestamp: "2026-08-14T05:33:03Z",
    app: { bundleIdentifier: "com.microsoft.edgemac", name: "Microsoft Edge", secureInput: true },
    keyboard: { target: { role: "AXTextField" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(typedUnderSecureInput.Activity, "Credential Entry");

  // An ordinary field must not pick up the credential language.
  const ordinary = parseSkysightEvent({
    id: 11, kind: "keyboard.text_input", timestamp: "2026-08-14T05:33:02Z",
    app: { bundleIdentifier: "com.openai.codex", name: "Codex" },
    keyboard: { text: "hello", target: { role: "AXTextArea", subrole: "AXSearchField" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(ordinary.Activity, "Text Input");
  assert.equal(ordinary.TargetSubrole, "AXSearchField");
  assert.doesNotMatch(ordinary.Description, /SECURE FIELD/);
});

test("selected items are captured so a Finder selection is not an empty row", () => {
  // These events carry no selectedText, so before this they produced a row with no payload at all.
  const row = parseSkysightEvent({
    id: 12, kind: "selection.changed", timestamp: "2026-08-14T05:34:00Z",
    app: { bundleIdentifier: "com.apple.finder", name: "Finder" },
    selection: {
      target: { role: "AXOutline" },
      selectedItems: [
        { role: "AXRow", subrole: "AXOutlineRow", title: "payroll-2026.xlsx" },
        { role: "AXRow", subrole: "AXOutlineRow", title: "client-list.csv" },
      ],
    },
  }, "/evidence/events.jsonl", {}, {}, {});

  assert.equal(row.SelectedItemCount, "2");
  assert.equal(row.SelectedItems, "payroll-2026.xlsx | client-list.csv");
  assert.equal(row.SelectedItemRoles, "AXOutlineRow, AXOutlineRow");
  assert.equal(row.Content, "payroll-2026.xlsx | client-list.csv", "payload no longer empty");
  assert.equal(row.Activity, "Item Selection");
  assert.match(row.Description, /Selected 2: payroll-2026\.xlsx/);

  // Real text selection still wins over the item list.
  const text = parseSkysightEvent({
    id: 13, kind: "selection.changed", timestamp: "2026-08-14T05:34:01Z",
    app: { bundleIdentifier: "com.microsoft.edgemac", name: "Edge" },
    selection: { selectedText: "highlighted", selectedItems: [{ role: "AXRow", title: "row" }] },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(text.Content, "highlighted");
  assert.equal(text.SelectedItemCount, "1", "items still recorded alongside");
});

test("mouse button, click count and element identity are recorded", () => {
  const row = parseSkysightEvent({
    id: 20, kind: "mouse.click", timestamp: "2026-08-14T05:40:00Z",
    app: { bundleIdentifier: "com.apple.finder", name: "Finder" },
    mouse: {
      button: "right", clickCount: 2,
      target: { role: "AXRow", identifier: "row-17", title: "payroll.xlsx", description: "spreadsheet, 2 MB" },
    },
  }, "/evidence/events.jsonl", {}, {}, {});

  assert.equal(row.MouseButton, "right", "right-click precedes Copy / Save As / Reveal in Finder");
  assert.equal(row.ClickCount, "2");
  assert.equal(row.TargetId, "row-17");
  assert.equal(row.TargetLabel, "payroll.xlsx");
  // description and title are different facts; description used to be dropped whenever title existed
  assert.equal(row.TargetDescription, "spreadsheet, 2 MB");
});

test("the per-event typed delta is kept only when it is not the tail of the field value", () => {
  const appended = parseSkysightEvent({
    id: 21, kind: "keyboard.text_input", timestamp: "2026-08-14T05:41:00Z",
    app: { bundleIdentifier: "com.openai.codex", name: "Codex" },
    keyboard: { text: "llo", target: { role: "AXTextArea", value: "hello" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(appended.TypedDelta, "", "plain forward typing adds nothing the value lacks");

  // Observed live in 121 of 276 cases: the value does not end with the delta, so the cumulative
  // value alone cannot reconstruct what was actually typed at this moment.
  const midEdit = parseSkysightEvent({
    id: 22, kind: "keyboard.text_input", timestamp: "2026-08-14T05:41:01Z",
    app: { bundleIdentifier: "com.openai.codex", name: "Codex" },
    keyboard: { text: "XYZ", target: { role: "AXTextArea", value: "heXYZllo" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(midEdit.TypedDelta, "XYZ");
  assert.equal(midEdit.Content, "heXYZllo", "cumulative value still primary");
});

test("a cross-app drag records where it landed and what was there", () => {
  const row = parseSkysightEvent({
    id: 23, kind: "mouse.drag", timestamp: "2026-08-14T05:42:00Z",
    mouse: {
      button: "left",
      origin: { app: { bundleIdentifier: "com.apple.finder", name: "Finder" }, window: { title: "Docs" }, element: { role: "AXRow", title: "secrets.txt" } },
      destination: {
        app: { bundleIdentifier: "com.tinyspeck.slackmacgap", name: "Slack" },
        window: { title: "#general", url: "https://app.slack.test/c/1" },
        element: { role: "AXTextArea", subrole: "AXSearchField", title: "Message #general", value: "draft text" },
      },
    },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(row.DestTargetLabel, "Message #general");
  assert.equal(row.DestContent, "draft text");
  assert.equal(row.DestUrl, "https://app.slack.test/c/1");
});

test("a cross-app drag records the destination subrole", () => {
  const row = parseSkysightEvent({
    id: 14, kind: "mouse.drag", timestamp: "2026-08-14T05:35:00Z",
    mouse: {
      button: "left",
      origin: { app: { bundleIdentifier: "com.apple.finder", name: "Finder" }, window: { title: "Docs" }, element: { role: "AXRow", title: "secrets.txt" } },
      destination: { app: { bundleIdentifier: "com.tinyspeck.slackmacgap", name: "Slack" }, window: { title: "#general" }, element: { role: "AXTextArea", subrole: "AXSearchField" } },
    },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(row.DestTargetRole, "AXTextArea");
  assert.equal(row.DestTargetSubrole, "AXSearchField");
  assert.equal(row.EventClass, CLASS_DATA_MOVEMENT, "drag is never masked by the app family");
});

/* --------------------------------------------------------------- coalescing */

test("coalesceTypedInput keeps the completed value and records the run", () => {
  const rows = [
    { EventKind: "keyboard.text_input", BundleId: "a", WindowTitle: "w", TargetRole: "AXTextArea", TargetLabel: "l", Content: "What ", Timestamp: "2026-08-14 05:28:32", EventId: "7", Description: "d" },
    { EventKind: "keyboard.text_input", BundleId: "a", WindowTitle: "w", TargetRole: "AXTextArea", TargetLabel: "l", Content: "What I was", Timestamp: "2026-08-14 05:28:44", EventId: "8", Description: "d" },
    { EventKind: "keyboard.text_input", BundleId: "a", WindowTitle: "w", TargetRole: "AXTextArea", TargetLabel: "l", Content: "What I was working on?", Timestamp: "2026-08-14 05:28:47", EventId: "9", Description: "d" },
    { EventKind: "keyboard.submit", BundleId: "a", WindowTitle: "w", Content: "", Timestamp: "2026-08-14 05:28:49", EventId: "10", Description: "d" },
  ];
  const out = coalesceTypedInput(rows);
  assert.equal(out.length, 2);
  assert.equal(out[0].Content, "What I was working on?");
  assert.equal(out[0].EventId, "9", "retains the last event of the run");
  assert.match(out[0].Description, /Coalesced 3 keystroke events from 2026-08-14 05:28:32 \(id 7–9\)/);
  assert.equal(out[1].EventKind, "keyboard.submit");
});

test("coalesceTypedInput survives interleaved selection/shortcut/click noise", () => {
  // The dominant real-world shape: Skysight interleaves selection.changed and keyboard.shortcut
  // between nearly every keystroke group, and a click (model picker) can land mid-composition.
  const typed = (v, id) => ({
    EventKind: "keyboard.text_input", BundleId: "a", WindowTitle: "w",
    TargetRole: "AXTextArea", TargetLabel: "Do anything",
    Content: v, Timestamp: `2026-08-14 05:28:${id}`, EventId: String(id), Description: "d",
  });
  const noise = (kind, id) => ({
    EventKind: kind, BundleId: "a", WindowTitle: "w", TargetRole: "AXStaticText",
    TargetLabel: "", Content: "", Timestamp: `2026-08-14 05:28:${id}`, EventId: String(id), Description: "d",
  });
  const rows = [
    typed("What ", 31),
    noise("selection.changed", 32),
    noise("keyboard.shortcut", 33),
    typed("What I was", 34),
    noise("mouse.click", 35),
    typed("What I was working on?", 36),
  ];
  const out = coalesceTypedInput(rows);
  const kept = out.filter((r) => r.EventKind === "keyboard.text_input");
  assert.equal(kept.length, 1, "one row for the whole composition");
  assert.equal(kept[0].Content, "What I was working on?");
  assert.equal(out.length, 4, "interleaved events are preserved, not dropped");
  assert.match(kept[0].Description, /Coalesced 3 keystroke events/);
});

test("coalesceTypedInput starts a new run after submit and on a non-continuation", () => {
  const typed = (v, id) => ({
    EventKind: "keyboard.text_input", BundleId: "a", WindowTitle: "w",
    TargetRole: "AXTextArea", TargetLabel: "f", Content: v,
    Timestamp: `2026-08-14 05:28:${id}`, EventId: String(id), Description: "d",
  });
  const submit = (id) => ({
    EventKind: "keyboard.submit", BundleId: "a", WindowTitle: "w",
    TargetRole: "AXTextArea", TargetLabel: "f", Content: "",
    Timestamp: `2026-08-14 05:28:${id}`, EventId: String(id), Description: "d",
  });

  // Two prompts in the same field, separated by a submit — must stay two rows even though the
  // second value happens to extend the first.
  const afterSubmit = coalesceTypedInput([typed("hello", 10), submit(11), typed("hello world", 12)])
    .filter((r) => r.EventKind === "keyboard.text_input");
  assert.equal(afterSubmit.length, 2);
  assert.equal(afterSubmit[0].Content, "hello");
  assert.equal(afterSubmit[1].Content, "hello world");

  // A value that is not a prefix either way is a fresh composition (field cleared and retyped).
  const reset = coalesceTypedInput([typed("abc", 20), typed("abcd", 21), typed("zzz", 22)])
    .filter((r) => r.EventKind === "keyboard.text_input");
  assert.equal(reset.length, 2);
  assert.equal(reset[0].Content, "abcd");
  assert.equal(reset[1].Content, "zzz");

  // Backspacing then retyping is still one composition (shared prefix "hel").
  const backspace = coalesceTypedInput([typed("hello", 30), typed("hell", 31), typed("help", 32)])
    .filter((r) => r.EventKind === "keyboard.text_input");
  assert.equal(backspace.length, 1);
  assert.equal(backspace[0].Content, "help");
});

test("coalesceTypedInput never collapses terminal scrollback snapshots", () => {
  // iTerm/Terminal expose the whole visible buffer as the field value. Successive snapshots share a
  // long prefix; collapsing them would erase the command/output timeline.
  const snap = (v, id) => ({
    EventKind: "keyboard.text_input", EventClass: CLASS_INPUT, AppClass: CLASS_TERMINAL,
    BundleId: "com.googlecode.iterm2",
    WindowTitle: "zsh", TargetRole: "AXTextArea", TargetLabel: "shell", Content: v,
    Timestamp: `2026-08-14 05:31:${id}`, EventId: String(id), Description: "d",
  });
  const rows = [
    snap("$ ls\nfile-a\nfile-b\n", 40),
    snap("$ ls\nfile-a\nfile-b\n$ whoami\n", 41),
    snap("$ ls\nfile-a\nfile-b\n$ whoami\nsubject\n", 42),
  ];
  const out = coalesceTypedInput(rows);
  assert.equal(out.length, 3, "every scrollback snapshot preserved");
  assert.ok(out.every((r) => !/Coalesced/.test(r.Description)));
});

test("scrollback is protected for terminals missing from the app table", () => {
  // Ghostty/Alacritty/Tabby are not in APP_CLASS_OVERRIDES. Recognising the shape of the payload —
  // a large AXTextArea value — keeps their command timeline from collapsing into one row.
  const snap = (v, id) => ({
    EventKind: "keyboard.text_input", EventClass: CLASS_INPUT, AppClass: "",
    BundleId: "com.mitchellh.ghostty",
    WindowTitle: "zsh", TargetRole: "AXTextArea", TargetLabel: "shell", Content: v,
    Timestamp: `2026-08-14 05:32:${id}`, EventId: String(id), Description: "d",
  });
  const base = "$ ls\n".repeat(500); // >= SCROLLBACK_MIN_CHARS
  const rows = [snap(base, 50), snap(`${base}$ whoami\n`, 51), snap(`${base}$ whoami\nsubject\n`, 52)];
  assert.ok(isScrollbackSnapshot(rows[0]), "recognised structurally, without the bundle table");
  assert.equal(coalesceTypedInput(rows).length, 3);

  // A short AXTextArea is an ordinary composition and must still coalesce.
  const short = [
    { ...snap("hel", 60), Content: "hel" },
    { ...snap("hello", 61), Content: "hello" },
  ];
  assert.equal(coalesceTypedInput(short).length, 1);
});

test("coalesceTypedInput follows delete-shortcut values across a typo correction", () => {
  // Live shape: a typo is corrected via delete-key shortcuts that carry the intermediate field
  // value. "…evnt" is not a prefix of "…events", so without reading the shortcut rows the run
  // would split into two prompts.
  const field = { BundleId: "a", WindowTitle: "w", TargetRole: "AXTextArea", TargetLabel: "Do anything" };
  const rows = [
    { ...field, EventKind: "keyboard.text_input", Content: "what are the evnt", Timestamp: "t1", EventId: "188", Description: "d" },
    { ...field, EventKind: "keyboard.shortcut", Content: "what are the evn", Timestamp: "t2", EventId: "189", Description: "d" },
    { ...field, EventKind: "keyboard.text_input", Content: "what are the events and apps", Timestamp: "t3", EventId: "249", Description: "d" },
  ];
  const out = coalesceTypedInput(rows);
  const typed = out.filter((r) => r.EventKind === "keyboard.text_input");
  assert.equal(typed.length, 1, "typo correction stays one composition");
  assert.equal(typed[0].Content, "what are the events and apps");
  assert.equal(out.length, 2, "the shortcut row is retained as independent evidence");
  assert.ok(out.some((r) => r.EventKind === "keyboard.shortcut" && r.EventId === "189"));
});

test("isTypingContinuation handles growth, backspacing and resets", () => {
  assert.equal(isTypingContinuation("", "a"), true);
  assert.equal(isTypingContinuation("What", "What I"), true);
  assert.equal(isTypingContinuation("What I", "What"), true);
  assert.equal(isTypingContinuation("What", "Where"), false);
});

test("coalesceTypedInput does not merge runs across different fields", () => {
  const rows = [
    { EventKind: "keyboard.text_input", BundleId: "a", WindowTitle: "w", TargetRole: "AXTextArea", TargetLabel: "one", Content: "abc", Timestamp: "t1", EventId: "1", Description: "d" },
    { EventKind: "keyboard.text_input", BundleId: "a", WindowTitle: "w", TargetRole: "AXTextArea", TargetLabel: "two", Content: "xyz", Timestamp: "t2", EventId: "2", Description: "d" },
  ];
  assert.equal(coalesceTypedInput(rows).length, 2);
});

/* ------------------------------------------------------------ segment layer */

test("readSegmentMetadata surfaces suppressed counts and open buckets", () => {
  const closed = readSegmentMetadata(FIXTURE_SEGMENT_1);
  assert.equal(closed.startedAt, "2026-08-14 05:20:00");
  assert.equal(closed.endedAt, "2026-08-14 05:30:00");
  assert.equal(closed.suppressedEventCount, 7);
  assert.equal(closed.open, false);

  const open = readSegmentMetadata(path.join(FIXTURE_SEGMENTS, "2026-08-14T05-40-00Z"));
  assert.equal(open.open, true, "endedAt:null means still being written");
  assert.equal(open.suppressedEventCount, null);
});

test("readSegmentMetadata keeps the recorded source path from the capture host", () => {
  // On a triage copy this is the only in-artifact proof of the original home, user and volume.
  const meta = readSegmentMetadata(FIXTURE_SEGMENT_1);
  assert.match(meta.recordedEventsPath, /^\/Users\/subject\/Library\/Group Containers\//);
  assert.equal(meta.recordedId, "2026-08-14T05-20-00Z");
});

/* ------------------------------------------------------- count reconciliation */

test("a segment whose record count matches its metadata is marked reconciled", async () => {
  const rows = await extractSegmentFile(FIXTURE_SEGMENT_1, {}, {}, { errors: 0 });
  const boundary = rows.find((r) => r.EventKind === "segment.boundary");
  assert.equal(rows._countDelta, 0);
  assert.equal(boundary.SegmentEventCount, "13");
  assert.equal(boundary.SegmentCountDelta, "0");
  assert.match(boundary.Content, /reconciled: record count matches metadata/);
  // The corrupt line is reported on its own terms, not folded into the count.
  assert.match(boundary.Content, /malformedLines=1/);
  assert.equal(rows.filter((r) => r.EventKind === "segment.integrity").length, 0);
  assert.equal(boundary.RecordedSourcePath, readSegmentMetadata(FIXTURE_SEGMENT_1).recordedEventsPath);
});

test("records removed after the count was written are flagged as a deletion lead", async () => {
  // What "clear the last 10 minutes" leaves behind: fewer records, same metadata count.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ch-integrity-"));
  const seg = path.join(dir, "2026-08-14T05-20-00Z");
  fs.mkdirSync(seg, { recursive: true });
  fs.writeFileSync(path.join(seg, "metadata.json"), JSON.stringify({
    startedAt: "2026-08-14T05:20:00Z", endedAt: "2026-08-14T05:30:00Z",
    eventCount: 10, suppressedEventCount: 0,
    eventsPath: "/Users/subject/evidence/events.jsonl", id: "2026-08-14T05-20-00Z",
  }));
  fs.writeFileSync(path.join(seg, "events.jsonl"), [
    { id: 1, kind: "mouse.click", timestamp: "2026-08-14T05:21:00Z", app: { bundleIdentifier: "a", name: "A" } },
    { id: 2, kind: "mouse.click", timestamp: "2026-08-14T05:22:00Z", app: { bundleIdentifier: "a", name: "A" } },
  ].map((o) => JSON.stringify(o)).join("\n"));

  const rows = await extractSegmentFile(seg, {}, {}, { errors: 0 });
  assert.equal(rows._countDelta, -8);
  const integrity = rows.find((r) => r.EventKind === "segment.integrity");
  assert.ok(integrity, "a shortfall gets its own row, not just a boundary note");
  assert.equal(integrity.Activity, "Record Count Short (derived)");
  assert.equal(integrity.SegmentCountDelta, "-8");
  assert.match(integrity.Content, /8 record\(s\) are missing/);
  assert.match(integrity.Content, /history-clear or a targeted deletion/);
  assert.match(integrity.Content, /not an observed event/);
  assert.equal(integrity.RecordedSourcePath, "/Users/subject/evidence/events.jsonl");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("an open bucket is not reconciled — its count is not final", async () => {
  const rows = await extractSegmentFile(
    path.join(FIXTURE_SEGMENTS, "2026-08-14T05-40-00Z"), {}, {}, { errors: 0 },
  );
  assert.equal(rows._countDelta, null, "no verdict while the recorder is still writing");
  assert.equal(rows.filter((r) => r.EventKind === "segment.integrity").length, 0);
  const boundary = rows.find((r) => r.EventKind === "segment.boundary");
  assert.match(boundary.Content, /count not reconciled/);
});

test("listSegmentDirs returns only buckets holding an events file, sorted", () => {
  const dirs = listSegmentDirs(FIXTURE_SEGMENTS).map((d) => path.basename(d));
  assert.deepEqual(dirs, ["2026-08-14T05-20-00Z", "2026-08-14T05-40-00Z"]);
});

test("detectSegmentGaps flags the missing 10-minute bucket as derived", () => {
  const gaps = detectSegmentGaps(
    ["2026-08-14T05-20-00Z", "2026-08-14T05-40-00Z"], FIXTURE_SEGMENTS, {},
  );
  assert.equal(gaps.length, 1);
  assert.equal(gaps[0].SegmentId, "2026-08-14T05-30-00Z");
  assert.equal(gaps[0].EventKind, "segment.gap");
  assert.equal(gaps[0].Timestamp, "2026-08-14 05:30:00");
  assert.match(gaps[0].Content, /not an observed event/);
  assert.equal(gaps[0].EventId, "", "synthetic rows carry no source event id");
});

test("a gap with a continuous id chain is reported as idle, not as evidence loss", () => {
  // Observed live: bucket 06-30 absent while ids ran 6347 -> 6348 straight through. Calling that a
  // tamper indicator would put a false lead in front of an analyst.
  const [gap] = detectSegmentGaps(
    ["2026-08-14T05-20-00Z", "2026-08-14T05-40-00Z"], FIXTURE_SEGMENTS, {},
    { "2026-08-14T05-20-00Z": { min: 1, max: 6347 }, "2026-08-14T05-40-00Z": { min: 6348, max: 6400 } },
  );
  assert.equal(gap.Activity, "Segment Gap (no activity)");
  assert.match(gap.Content, /run continuously/);
  assert.match(gap.Content, /NOT evidence of deletion/);
});

test("a gap with a broken id chain reports the unaccounted-for count without claiming deletion", () => {
  const ranges = new Map([
    ["2026-08-14T05-20-00Z", { min: 1, max: 100 }],
    ["2026-08-14T05-40-00Z", { min: 151, max: 200 }],
  ]);
  const [gap] = detectSegmentGaps(
    ["2026-08-14T05-20-00Z", "2026-08-14T05-40-00Z"], FIXTURE_SEGMENTS, {}, ranges,
  );
  assert.equal(gap.Activity, "Segment Gap (ids unaccounted for)");
  assert.match(gap.Content, /50 event id\(s\) are unaccounted for/);
  assert.match(gap.Content, /not a finding of deletion/);
  assert.match(gap.Content, /Ids are not a suppression count/);
});

test("the extractor feeds real id ranges into gap classification", async () => {
  // End-to-end guard: the ranges must be collected from parsed rows, and synthetic boundary rows
  // (EventId "") must not drag a bucket's minimum to zero — that would silently clear every gap.
  const rows = await extractComputerHistoryDir(FIXTURE_ROOT, {}, {});
  const gap = rows.find((r) => r.EventKind === "segment.gap");
  assert.equal(gap.Activity, "Segment Gap (ids unaccounted for)");
  assert.match(gap.Content, /26 event id\(s\) are unaccounted for across this bucket \(13 → 40\)/);
});

test("a gap spanning a recorder restart is unassessed, never cleared", () => {
  // The counter restarts at 1 with each recorder session, so ids either side of the hole belong to
  // different runs. Subtracting them yields a NEGATIVE "missing" count, which lands in the "<= 0"
  // branch and reads as reassurance: on one live capture this cleared 183 of 186 gap rows with
  // "ids run continuously (17169 → 1)" — thirteen-hour holes it had never actually assessed.
  const [gap] = detectSegmentGaps(
    ["2026-08-14T08-10-00Z", "2026-08-14T21-20-00Z"], FIXTURE_SEGMENTS, {},
    {
      "2026-08-14T08-10-00Z": { min: 15897, max: 17169 },
      "2026-08-14T21-20-00Z": { min: 1, max: 513, sessionStart: true },
    },
  );
  assert.equal(gap.Activity, "Segment Gap (recorder restarted — unassessed)");
  assert.match(gap.Content, /CANNOT assess/);
  assert.match(gap.Content, /neither confirmed nor cleared/);
  assert.doesNotMatch(gap.Content, /NOT evidence of deletion/);
  assert.doesNotMatch(gap.Content, /no events are missing/);
});

test("a restart is caught from the id reset alone, without a session.started marker", () => {
  // Belt and braces: the reset is detectable even when the flag never made it through (a streaming
  // sink, a truncated first bucket). A counter that went backwards cannot be a continuous chain.
  const [gap] = detectSegmentGaps(
    ["2026-08-14T05-20-00Z", "2026-08-14T05-40-00Z"], FIXTURE_SEGMENTS, {},
    { "2026-08-14T05-20-00Z": { min: 1, max: 900 }, "2026-08-14T05-40-00Z": { min: 4, max: 60 } },
  );
  assert.equal(gap.Activity, "Segment Gap (recorder restarted — unassessed)");
});

test("a gap with no id evidence is marked unassessed rather than guessed at", () => {
  const [gap] = detectSegmentGaps(
    ["2026-08-14T05-20-00Z", "2026-08-14T05-40-00Z"], FIXTURE_SEGMENTS, {},
  );
  assert.equal(gap.Activity, "Segment Gap (unassessed)");
  assert.match(gap.Content, /neither confirmed nor cleared/);
});

test("detectSegmentGaps returns nothing for a contiguous or single-bucket run", () => {
  assert.equal(detectSegmentGaps(["2026-08-14T05-20-00Z"], "/s", {}).length, 0);
  assert.equal(
    detectSegmentGaps(["2026-08-14T05-20-00Z", "2026-08-14T05-30-00Z"], "/s", {}).length, 0,
  );
});

/* ------------------------------------------------------------- summary (.md) */

test("parseSummaryFrontmatter reads scalars and inline lists without a YAML dep", () => {
  const { fields, body } = parseSummaryFrontmatter(
    "---\ntitle: Some title\napplications: [com.a, com.b]\n---\n\n## Body\ntext\n",
  );
  assert.equal(fields.title, "Some title");
  assert.equal(fields.applications, "com.a, com.b");
  assert.match(body, /## Body/);
  assert.doesNotMatch(body, /^---/);
});

test("parseSummaryFrontmatter reads the nested suggestion block", () => {
  const { fields, nested } = parseSummaryFrontmatter(
    "---\ntitle: T\nsuggestion:\n  type: skill\n  name: Parser build\n  description: Do the thing\n"
    + "applications: [com.a]\n---\nbody\n",
  );
  assert.equal(fields.title, "T");
  assert.equal(fields.applications, "com.a");
  assert.deepEqual(nested.suggestion, { type: "skill", name: "Parser build", description: "Do the thing" });
});

test("extractSummaryCitations pulls the evidence paths out of the body", () => {
  const cites = extractSummaryCitations(
    "## Recording summary\ntext\n\n## Citations\n\n- /evidence/segments/A/events.jsonl\n"
    + "- /evidence/segments/A/metadata.json\n",
  );
  assert.equal(cites, "/evidence/segments/A/events.jsonl\n/evidence/segments/A/metadata.json");
  assert.equal(extractSummaryCitations("## Body only\ntext"), "");
});

test("click multiplicity is named by meaning, keeping Activity low-cardinality", () => {
  const click = (clickCount) => describeActivity("mouse.click", { mouse: { clickCount } }, "", "", "");
  assert.equal(click(undefined), "Click");
  assert.equal(click(1), "Click");
  assert.equal(click(2), "Double-Click");   // open / launch / select word
  assert.equal(click(3), "Triple-Click");   // select line / paragraph
  // macOS keeps incrementing while clicks stay inside the double-click interval, so x4..x10 were
  // ten separate Activity values for one behaviour. The exact count lives in ClickCount.
  for (const n of [4, 5, 6, 7, 8, 9, 10, 25]) assert.equal(click(n), "Multi-Click");
});

test("mouse modifiers reach KeyChord — a command-click is not a plain click", () => {
  // command-click on a link opens it in a background tab: deliberate non-navigation, the pattern
  // behind bulk-opening search results. It was being dropped entirely.
  const cmd = parseSkysightEvent({
    id: 40, kind: "mouse.click", timestamp: "2026-08-14T05:40:00Z",
    app: { bundleIdentifier: "com.microsoft.edgemac", name: "Microsoft Edge" },
    window: { title: "Results", url: "https://example.test/results" },
    mouse: { button: "left", modifiers: ["command"], target: { role: "AXLink", title: "next" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(cmd.KeyChord, "command");
  assert.equal(cmd.Activity, "Click", "the modifier belongs in KeyChord, not in Activity");

  const shift = parseSkysightEvent({
    id: 41, kind: "mouse.click", timestamp: "2026-08-14T05:40:01Z",
    app: { bundleIdentifier: "com.apple.finder", name: "Finder" },
    mouse: { button: "left", modifiers: ["shift"], target: { role: "AXRow" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(shift.KeyChord, "shift");

  // Keyboard chords keep working unchanged.
  const kb = parseSkysightEvent({
    id: 42, kind: "keyboard.shortcut", timestamp: "2026-08-14T05:40:02Z",
    app: { bundleIdentifier: "com.apple.finder", name: "Finder" },
    keyboard: { modifiers: ["command"], keyEquivalent: "c", target: { role: "AXRow" } },
  }, "/evidence/events.jsonl", {}, {}, {});
  assert.equal(kb.KeyChord, "command+c");
});

test("a summary body is split into its distinct assertions", () => {
  const rows = parseSummaryFileRows(FIXTURE_SUMMARY, { user: "subject" }, {});
  const kinds = rows.map((r) => r.EventKind);
  assert.ok(kinds.includes("summary.10min"), "the parent activity summary is still emitted");
  assert.ok(kinds.includes("summary.profile"));
  assert.ok(kinds.includes("summary.priorcontext"));

  // The user profile is the largest and highest-value section, and it outlives the raw purge —
  // buried in ScreenText it was neither filterable nor discoverable.
  const profile = rows.find((r) => r.EventKind === "summary.profile");
  assert.equal(profile.Activity, "User Profile (model-inferred)");
  assert.match(profile.Content, /telco/, "it names a search term the raw stream may no longer hold");
  assert.doesNotMatch(profile.Content, /MODEL-INFERRED/, "the caveat must not pollute Content");
  assert.match(profile.Description, /MODEL-INFERRED PROFILE/);
  assert.match(profile.Description, /persists after the ~48h raw purge/);

  // Prior context describes activity from OUTSIDE this window — the row timestamp does not bound it.
  const prior = rows.find((r) => r.EventKind === "summary.priorcontext");
  assert.match(prior.Description, /CARRIED FORWARD/);
  assert.match(prior.Description, /NOT the time of the activity it describes/);

  // Sub-rows sort with the window they were written in.
  const parent = rows.find((r) => r.EventKind === "summary.10min");
  assert.equal(profile.Timestamp, parent.Timestamp);
  assert.equal(profile.SegmentId, parent.SegmentId);
});

test("extractSummarySection stops at the next heading and tolerates absence", () => {
  const body = "## A\nalpha\n\n### B\nbravo\n\n## C\ncharlie\n";
  assert.equal(extractSummarySection(body, "A"), "alpha");
  assert.equal(extractSummarySection(body, "B"), "bravo");
  assert.equal(extractSummarySection(body, "Nope"), "");
  assert.equal(extractSummarySection("", "A"), "");
});

test("Skysight-derived consolidated memory is collected — it outlives the artifacts", () => {
  // The durable Codex memory store is a THIRD copy of observed activity, one directory up from the
  // artifacts everyone collects. It is not purged at 48h and not removed by clearing Computer
  // History, so on a stale host it can be the only surviving record.
  const rows = collectSkysightDerivedMemory(FIXTURE_ROOT, { user: "subject" });
  assert.ok(rows.length >= 3, `expected tagged + citing lines, got ${rows.length}`);

  for (const r of rows) {
    assert.equal(r.EventKind, "memory.consolidated");
    assert.equal(r.Activity, "Consolidated Memory (Skysight-derived)");
    assert.equal(r.EventClass, "Narrative");
    assert.match(r.Description, /NOT purged with the 48h event stream/);
    // No per-line time exists in these files; the mtime must be labelled as what it is.
    assert.match(r.Description, /Timestamp is the file mtime/);
    assert.ok(Number(r.LineNumber) > 0, "each row points back to its line");
  }

  const files = new Set(rows.map((r) => path.basename(r.SourceFile)));
  assert.ok(files.has("memory_summary.md"));
  assert.ok(files.has("MEMORY.md"));

  // Ordinary Codex conversation memory is a different artifact family and must stay out.
  assert.ok(
    !rows.some((r) => /Unrelated conversation memory|must not be imported/.test(r.Content)),
    "untagged, non-citing blocks are not swept in",
  );
});

test("the Computer Use approvals file is not presented as the recording scope", () => {
  const rows = collectFeatureState(FIXTURE_ROOT, {});
  const approvals = rows.find((r) => r.Activity === "Computer Use Agent Approvals");
  assert.ok(approvals, "the approvals file is still recorded, as what it actually is");
  assert.equal(approvals.EventClass, "Configuration");
  assert.equal(approvals.EventKind, "feature.state");

  // The whole point of the row. This file belongs to Computer Use (ChatGPT DRIVING the Mac), not
  // to Computer History recording: on a live host it listed one bundle while the recorder captured
  // 38, with an mtime three months older than the feature. Reading it as a coverage map inverts
  // every conclusion drawn from silence.
  assert.match(approvals.Content, /NOT the recording scope/);
  assert.match(approvals.Content, /approved to CONTROL/);
  assert.match(approvals.Content, /UNKNOWN/);
  assert.match(approvals.Content, /not evidence the app was unused/);
  assert.doesNotMatch(approvals.Activity, /^App Approvals$/);
});

test("collectFeatureState records Computer History plugin vs Computer Use MCP independently", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ch-feat-"));
  try {
    const codex = path.join(home, ".codex");
    fs.mkdirSync(codex, { recursive: true });
    fs.mkdirSync(path.join(home, "Library/Group Containers"), { recursive: true });
    fs.writeFileSync(path.join(codex, "config.toml"), [
      `[plugins."computer-history@openai-bundled"]`,
      `enabled = true`,
      ``,
      `[mcp_servers.computer-use]`,
      `enabled = false`,
      ``,
    ].join("\n"));
    const pluginDir = path.join(
      codex, "plugins/cache/openai-bundled/computer-history/1.0.1000761/.codex-plugin",
    );
    fs.mkdirSync(pluginDir, { recursive: true });
    fs.writeFileSync(path.join(pluginDir, "plugin.json"), JSON.stringify({
      name: "computer-history",
      version: "1.0.1000761",
      description: "Ask ChatGPT about what you were doing recently",
    }));

    const rows = collectFeatureState(home, {});
    const enabled = rows.find((r) => r.Activity === "Feature Enabled");
    const cua = rows.find((r) => r.Activity === "Computer Use Agent MCP Disabled");
    const plugin = rows.find((r) => r.Activity === "Computer History Plugin Installed");
    assert.ok(enabled);
    assert.ok(cua);
    assert.match(cua.Content, /independent of Computer History/);
    assert.ok(plugin);
    assert.match(plugin.Content, /1\.0\.1000761/);

    const kept = dedupeRows(rows);
    assert.equal(
      kept.filter((r) => r.EventKind === "feature.state").length,
      rows.filter((r) => r.EventKind === "feature.state").length,
      "two config.toml feature.state rows must not collapse",
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("parseSummaryFile emits a Narrative row timestamped from the filename", () => {
  const row = parseSummaryFile(FIXTURE_SUMMARY, { user: "subject" }, {});
  assert.equal(row.EventClass, CLASS_NARRATIVE);
  assert.equal(row.EventKind, "summary.10min");
  assert.equal(row.Activity, "Activity Summary (10min)");
  assert.equal(row.Timestamp, "2026-08-14 05:20:00");
  assert.equal(row.TargetLabel, "Computer History work recall");
  assert.equal(row.AppName, "com.openai.codex, com.microsoft.edgemac, ru.keepcoder.Telegram");
  assert.equal(row.User, "subject");
  assert.match(row.ScreenText, /## Memory summary/);
});

/* ------------------------------------------------------------- integration */

test("extractSegmentFile emits a boundary row and tolerates malformed lines", async () => {
  const parseStats = { errors: 0 };
  const rows = await extractSegmentFile(FIXTURE_SEGMENT_1, { user: "subject" }, {}, parseStats);

  const boundary = rows.find((r) => r.EventKind === "segment.boundary");
  assert.ok(boundary, "one boundary row per segment");
  assert.equal(boundary.SegmentSuppressed, "7");
  assert.match(boundary.Content, /suppressedEventCount=7/);

  assert.ok(parseStats.errors >= 1, "malformed JSONL line counted, not fatal");
  assert.ok(rows.some((r) => r.EventKind === "session.started"));
  assert.ok(rows.every((r) => r.SegmentId === "2026-08-14T05-20-00Z"));
});

test("extractComputerHistoryDir merges both artifact families from a triage root", async () => {
  const rows = await extractComputerHistoryDir(FIXTURE_ROOT, { user: "subject", host: "MAC-01" });

  assert.ok(rows.length > 10);
  assert.deepEqual(Object.keys(rows[0]), COMPUTER_HISTORY_COLUMNS,
    "row shape must match the declared column order");

  // Sorted ascending, RecordId sequential.
  for (let i = 1; i < rows.length; i++) {
    assert.ok(rows[i - 1].Timestamp <= rows[i].Timestamp, "rows sorted by timestamp");
  }
  assert.equal(rows[0].RecordId, "1");
  assert.equal(rows[rows.length - 1].RecordId, String(rows.length));

  const classes = new Set(rows.map((r) => r.EventClass));
  assert.ok(classes.has(CLASS_SESSION));
  assert.ok(classes.has(CLASS_WEB));
  assert.ok(classes.has(CLASS_DATA_MOVEMENT));
  assert.ok(classes.has(CLASS_NARRATIVE));
  assert.ok(new Set(rows.map((r) => r.AppClass)).has(CLASS_TERMINAL));

  // Keystroke run collapsed to the completed prompt.
  const typed = rows.filter((r) => r.EventKind === "keyboard.text_input" && r.BundleId === "com.openai.codex");
  assert.equal(typed.length, 1);
  assert.equal(typed[0].Content, "What I was working on yesterday?");

  // Telegram is Tier 3: outbound typing captured, no screen content.
  const telegramTyped = rows.find((r) => r.BundleId === "ru.keepcoder.Telegram" && r.EventKind === "keyboard.text_input");
  assert.equal(telegramTyped.Content, "sending a reply");
  assert.equal(telegramTyped.FidelityTier, "3");
  // Typing in a messaging app is still Input — that is how an analyst finds captured outbound text.
  assert.equal(telegramTyped.EventClass, CLASS_INPUT);
  assert.equal(telegramTyped.AppClass, CLASS_COMMUNICATION);

  const stats = rows._computerHistoryStats;
  assert.equal(stats.segmentCount, 2);
  assert.equal(stats.summaryCount, 1);
  assert.equal(stats.gapCount, 1);
  assert.equal(stats.suppressedTotal, 7);
  assert.ok(rows._parseErrors >= 1);

  assert.ok(rows.every((r) => r.User === "subject" && r.Host === "MAC-01"));
});

test("extractComputerHistoryDir honours rawKeystroke and gap opt-outs", async () => {
  const rows = await extractComputerHistoryDir(FIXTURE_ROOT, {}, {
    coalesceTypedInput: false, detectGaps: false, includeSegmentBoundaries: false,
  });
  const typed = rows.filter((r) => r.EventKind === "keyboard.text_input" && r.BundleId === "com.openai.codex");
  assert.equal(typed.length, 3, "every keystroke row retained");
  assert.equal(rows.filter((r) => r.EventKind === "segment.gap").length, 0);
  assert.equal(rows.filter((r) => r.EventKind === "segment.boundary").length, 0);
});

test("extractComputerHistoryPath accepts a single events file and a single summary", async () => {
  const eventsOnly = await extractComputerHistoryPath(path.join(FIXTURE_SEGMENT_1, "events.jsonl"));
  assert.ok(eventsOnly.some((r) => r.EventKind === "session.started"));
  assert.ok(eventsOnly.every((r) => r.SegmentId === "2026-08-14T05-20-00Z"));

  // One summary file yields the activity summary plus a row per distinct assertion in its body.
  const summaryOnly = await extractComputerHistoryPath(FIXTURE_SUMMARY);
  assert.equal(summaryOnly.length, 3);
  assert.ok(summaryOnly.every((r) => r.EventClass === CLASS_NARRATIVE));
  assert.deepEqual(
    summaryOnly.map((r) => r.EventKind),
    ["summary.10min", "summary.priorcontext", "summary.profile"],
  );
  assert.deepEqual(summaryOnly.map((r) => r.RecordId), ["1", "2", "3"]);
});

test("extractComputerHistoryPath rejects unrelated paths with a clear message", async () => {
  await assert.rejects(
    () => extractComputerHistoryPath(path.join(os.tmpdir(), "definitely-missing-irflow-ch")),
    /Path does not exist/,
  );

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ch-"));
  try {
    await assert.rejects(
      () => extractComputerHistoryPath(tmp),
      /No ChatGPT Computer History \(Skysight\) artifacts found/,
    );
    const stray = path.join(tmp, "notes.txt");
    fs.writeFileSync(stray, "hello");
    await assert.rejects(() => extractComputerHistoryPath(stray), /Expected a Skysight events\.jsonl/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

/* --------------------------------------------------------- IPC / worker wiring */

/* ----------------------------------------------------------------- identity */

test("decodeUuidV7 dates a v7 id and refuses every other version", () => {
  // Codex conversation ids are v7, so the id alone places the conversation on the timeline.
  assert.equal(decodeUuidV7("019ffebe-4d0f-7e22-97f4-e7ff2c2acd82"), 1786685312271);
  assert.equal(
    new Date(decodeUuidV7("019ffebe-4d0f-7e22-97f4-e7ff2c2acd82")).toISOString(),
    "2026-08-14T05:28:32.271Z",
  );
  assert.equal(decodeUuidV7("019f94e3-2f54-4f17-aeb8-19a273362c5a"), null, "v4 carries no time");
  assert.equal(decodeUuidV7("not-a-uuid"), null);
  assert.equal(decodeUuidV7(""), null);
  assert.equal(decodeUuidV7(null), null);
});

/** A home-shaped tree with the sibling attribution artifacts. */
function buildIdentityHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ch-home-"));
  const prefs = path.join(home, "Library/Preferences");
  const codex = path.join(home, ".codex");
  fs.mkdirSync(prefs, { recursive: true });
  fs.mkdirSync(path.join(home, "Library/Group Containers"), { recursive: true });
  fs.mkdirSync(codex, { recursive: true });

  // Two account-scoped preference files = two ChatGPT accounts used on this host.
  for (const id of ["9097b427-4a0c-4a3b-b588-c8eeb7312c08", "11112222-3333-4444-5555-666677778888"]) {
    fs.writeFileSync(path.join(prefs, `com.openai.chat.RemoteFeatureFlags.${id}.plist`), "");
  }
  fs.writeFileSync(path.join(codex, "installation_id"), "5e8ebfa2-4d11-49fd-9da4-07d9c4f199c5\n");
  fs.writeFileSync(path.join(prefs, "com.openai.chat.StatsigService.plist"), [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`,
    `<plist version="1.0"><dict>`,
    `<key>accountID</key><string>9097b427-4a0c-4a3b-b588-c8eeb7312c08</string>`,
    `<key>userEmail</key><string>subject@example.test</string>`,
    `<key>userID</key><string>user-TESTID</string>`,
    `<key>hasAnyPaidPlanAccount</key><true/>`,
    `<key>totalAccounts</key><integer>1</integer>`,
    `</dict></plist>`,
  ].join("\n"));

  const claims = {
    email: "subject@example.test", name: "Test Subject", sub: "auth0|abc123",
    auth_provider: "password", auth_time: 1780000000,
    "https://api.openai.com/auth": {
      chatgpt_account_id: "9097b427-4a0c-4a3b-b588-c8eeb7312c08",
      chatgpt_user_id: "user-TESTID", chatgpt_plan_type: "pro",
      organizations: [{ id: "org-TEST", role: "owner" }],
    },
  };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  fs.writeFileSync(path.join(codex, "auth.json"), JSON.stringify({
    auth_mode: "chatgpt",
    tokens: {
      id_token: `eyJhbGciOiJSUzI1NiJ9.${b64(claims)}.SIGNATURE_MUST_NEVER_BE_STORED`,
      access_token: "eyJhbGciOiJSUzI1NiJ9.ACCESS_TOKEN_SECRET.sig",
      refresh_token: "rt.1.REFRESH_TOKEN_SECRET",
      account_id: "9097b427-4a0c-4a3b-b588-c8eeb7312c08",
    },
  }));

  fs.writeFileSync(path.join(codex, ".codex-global-state.json"), JSON.stringify({
    "electron-local-remote-control-environment-id": "env_e_testenv",
    "thread-titles": {
      "019ffebe-4d0f-7e22-97f4-e7ff2c2acd82": "kept",
      "019fea8b-28d5-7fb0-8d50-c9f13e7330a8": "removed",
    },
    "electron-persisted-atom-state": {
      "codex-writing-block-deleted-thread-v1:019fea8b-28d5-7fb0-8d50-c9f13e7330a8": true,
    },
  }));
  return home;
}

test("findIdentityRoot walks past an app container to the real home", () => {
  const home = buildIdentityHome();
  // The CUAService container has its OWN Library/Preferences, which used to stop the walk here.
  const container = path.join(home, "Library/Group Containers", "2DC432GLL2.com.openai.sky.CUAService");
  fs.mkdirSync(path.join(container, "Library/Preferences"), { recursive: true });
  assert.equal(fs.realpathSync(findIdentityRoot(container)), fs.realpathSync(home));
  fs.rmSync(home, { recursive: true, force: true });
});

test("account UUIDs are read from preference filenames, and two files mean two accounts", () => {
  const home = buildIdentityHome();
  const accounts = listAccountPlists(path.join(home, "Library/Preferences"));
  assert.equal(accounts.length, 2);
  assert.ok(accounts.some((a) => a.accountId === "9097b427-4a0c-4a3b-b588-c8eeb7312c08"));

  const rows = collectIdentityArtifacts(home, { user: "subject" }, {});
  const acct = rows.filter((r) => r.EventKind === "identity.account");
  assert.equal(acct.length, 2);
  assert.match(acct[0].Activity, /direct/, "attribution strength is stated on the row");
  assert.match(acct[0].Content, /more than one ChatGPT account has been used/);
  fs.rmSync(home, { recursive: true, force: true });
});

test("StatsigService.plist binds email to the account UUID without reading auth.json", () => {
  const home = buildIdentityHome();
  const parsed = readChatgptStatsigServicePlist(
    path.join(home, "Library/Preferences/com.openai.chat.StatsigService.plist"),
  );
  assert.equal(parsed.email, "subject@example.test");
  assert.equal(parsed.accountId, "9097b427-4a0c-4a3b-b588-c8eeb7312c08");
  assert.equal(parsed.userId, "user-TESTID");
  assert.equal(parsed.paid, true);

  const rows = collectIdentityArtifacts(home, { user: "subject" }, {});
  const sig = rows.find((r) => r.EventKind === "identity.statsig_account");
  assert.ok(sig);
  assert.match(sig.Activity, /direct/);
  assert.match(sig.Content, /email=subject@example\.test/);
  assert.match(sig.Content, /no tokens/);
  fs.rmSync(home, { recursive: true, force: true });
});

test("identity rows carry the claims but never the tokens", () => {
  const home = buildIdentityHome();
  const rows = collectIdentityArtifacts(home, { user: "subject" }, {});
  const auth = rows.find((r) => r.EventKind === "identity.auth");

  assert.equal(auth.Identifier, "9097b427-4a0c-4a3b-b588-c8eeb7312c08");
  assert.match(auth.Content, /email=subject@example\.test/);
  assert.match(auth.Content, /user=user-TESTID/);
  assert.match(auth.Content, /plan=pro/);
  assert.match(auth.Content, /orgs=org-TEST \(owner\)/);
  assert.equal(auth.Timestamp, "2026-05-28 20:26:40", "timestamped from the token's auth_time");
  assert.match(auth.Content, /treat auth\.json as credential material/);

  // The whole row set must be free of bearer material — this is exported to CSV.
  const dumped = JSON.stringify(rows);
  for (const secret of ["SIGNATURE_MUST_NEVER_BE_STORED", "ACCESS_TOKEN_SECRET",
    "REFRESH_TOKEN_SECRET", "rt.1."]) {
    assert.ok(!dumped.includes(secret), `token material leaked into rows: ${secret}`);
  }
  fs.rmSync(home, { recursive: true, force: true });
});

test("a deleted Codex thread is dated from its own id and flagged for reconstruction", () => {
  const home = buildIdentityHome();
  const rows = collectIdentityArtifacts(home, {}, {});

  const deleted = rows.filter((r) => r.EventKind === "codex.thread.deleted");
  assert.equal(deleted.length, 1);
  assert.equal(deleted[0].Identifier, "019fea8b-28d5-7fb0-8d50-c9f13e7330a8");
  assert.equal(deleted[0].Timestamp, "2026-08-10 07:20:16");
  assert.equal(deleted[0].EventClass, "Integrity");
  assert.match(deleted[0].Content, /deleting the conversation does not delete the record of it/);

  const kept = rows.filter((r) => r.EventKind === "codex.thread.created");
  assert.equal(kept.length, 1);
  assert.equal(kept[0].Identifier, "019ffebe-4d0f-7e22-97f4-e7ff2c2acd82");

  // Device pseudonyms must be labelled as such, never as accounts.
  const install = rows.find((r) => r.EventKind === "identity.installation_id");
  assert.match(install.Activity, /device-pseudonym/);
  assert.match(install.Content, /different namespace from/);
  fs.rmSync(home, { recursive: true, force: true });
});

/* ------------------------------------------------- recovery of cleared summaries */

/** Build a memories-shaped git repo, commit a summary, then clear it — as the UI's clear does. */
function buildClearedMemoriesRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ch-memories-"));
  const resources = path.join(root, "extensions/skysight/resources");
  fs.mkdirSync(resources, { recursive: true });
  const name = "2026-08-14T05-20-00-jChV-10min-memory-summary.md";
  fs.writeFileSync(path.join(resources, name), [
    "---",
    "title: Credential access and staging",
    "description: The subject opened a password manager and staged files for transfer.",
    "applications: [in.sinew.Enpass-Desktop, com.apple.finder]",
    "suggestion:",
    "  type: skill",
    "  name: Staging review",
    "---",
    "",
    "## Recording summary",
    "The subject copied two files to a staging folder.",
    "",
    "## Citations",
    "",
    "- /Users/subject/evidence/segments/2026-08-14T05-20-00Z/events.jsonl",
    "",
  ].join("\n"));

  const git = (args) => execFileSync("git", ["-C", root, ...args], {
    stdio: "pipe",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t.test",
      GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t.test",
      GIT_AUTHOR_DATE: "2026-08-14T09:00:00Z", GIT_COMMITTER_DATE: "2026-08-14T09:00:00Z",
    },
  });
  git(["init", "-q"]);
  git(["add", "-A"]);
  git(["commit", "-qm", "baseline"]);
  fs.rmSync(path.join(resources, name)); // the user clears their history
  git(["add", "-A"]);
  git(["commit", "-qm", "clear history"]);
  return { root, resources };
}

test("a summary cleared by the user is recovered from the memories git repo", async (t) => {
  let repo;
  try { repo = buildClearedMemoriesRepo(); } catch { t.skip("git unavailable"); return; }

  const gitDir = findMemoriesGitDir(repo.resources);
  assert.equal(gitDir, path.join(repo.root, ".git"));

  const rows = await recoverDeletedSummaries(repo.resources, { user: "subject" }, {});
  assert.equal(rows.length, 1);
  const [row] = rows;

  // It sorts into the timeline where the ACTIVITY happened, not where the deletion happened.
  assert.equal(row.Timestamp, "2026-08-14 05:20:00");
  assert.equal(row.EventKind, "summary.deleted");
  assert.equal(row.EventClass, "Integrity");
  assert.match(row.Activity, /Deleted Activity Summary \(10min, recovered\)/);
  assert.match(row.Content, /RECOVERED FROM GIT/);
  assert.match(row.Content, /deleted from the memories repository at 2026-08-14 09:00:00/);
  // The recovered content itself must survive, or recovery is pointless.
  assert.match(row.Content, /opened a password manager/);
  assert.match(row.ScreenText, /copied two files to a staging folder/);
  assert.match(row.SummaryCitations, /2026-08-14T05-20-00Z\/events\.jsonl/);
  assert.equal(row.TargetLabel, "Credential access and staging");
  assert.match(row.SummarySuggestion, /Staging review/);

  fs.rmSync(repo.root, { recursive: true, force: true });
});

test("recovery is a no-op when there is no repository, and never throws", async () => {
  const bare = fs.mkdtempSync(path.join(os.tmpdir(), "ch-norepo-"));
  assert.equal(findMemoriesGitDir(bare), null);
  assert.deepEqual(await recoverDeletedSummaries(bare, {}, {}), []);
  fs.rmSync(bare, { recursive: true, force: true });
});

test("parseLogOutput pairs each commit with the files it removed", () => {
  const commits = parseLogOutput(
    "abc123\x1f2026-08-14T09:00:00Z\nextensions/skysight/resources/a.md\n"
    + "extensions/skysight/resources/b.md\n"
    + "def456\x1f2026-08-13T09:00:00Z\nextensions/skysight/resources/c.md\n"
    + "unrelated/other.md\n",
  );
  assert.equal(commits.length, 2);
  assert.deepEqual(commits[0].files, [
    "extensions/skysight/resources/a.md", "extensions/skysight/resources/b.md",
  ]);
  assert.equal(commits[1].files.length, 1, "paths outside the skysight tree are ignored");
});

test("registerAiHistoryHandlers exposes the decode-computer-history channel", () => {
  const registerAiHistoryHandlers = require("../electron/ipc/ai-history-handlers");
  const channels = [];
  const safeHandle = (channel) => { channels.push(channel); };
  registerAiHistoryHandlers(safeHandle, () => {}, {});
  assert.ok(channels.includes("decode-computer-history"));
  assert.ok(channels.includes("decode-ai-history"), "existing channel still registered");
});

test("computer-history worker builds an import notice that carries the coverage caveats", () => {
  const { buildImportNotice } = require("../electron/jobs/computer-history-worker");

  assert.equal(buildImportNotice(null, 0), null);

  const notice = buildImportNotice(
    { segmentCount: 6, summaryCount: 2, gapCount: 1, suppressedTotal: 93 }, 4,
  );
  assert.match(notice, /6 segment bucket\(s\)/);
  assert.match(notice, /2 derived activity summaries/);
  assert.match(notice, /1 missing 10-minute bucket/);
  assert.match(notice, /neither is by itself a finding of tampering/);
  assert.match(notice, /93 event\(s\) were recorded as suppressed/);
  assert.match(notice, /only authoritative figure for suppression/);
  assert.match(notice, /4 malformed JSONL line\(s\) skipped/);
  // The Tier 3 caveat must always ship with the import, not only when gaps exist.
  assert.match(notice, /one side of a conversation/);

  const clean = buildImportNotice({ segmentCount: 1, summaryCount: 1, gapCount: 0, suppressedTotal: 0 }, 0);
  assert.match(clean, /1 derived activity summary/, "singular form");
  assert.doesNotMatch(clean, /missing 10-minute/);
  assert.match(clean, /one side of a conversation/);
  // These caveats must ship on EVERY import — they qualify how the columns are read.
  assert.match(clean, /EventId gaps are NOT a suppression count/);
  assert.match(clean, /diffFromPrevious.*understate/s);
  assert.match(clean, /Filter typed content on EventClass = Input/);
  assert.match(clean, /resolved once per application/);
  // Integrity, recovery and coverage findings appear only when there is something to report.
  assert.doesNotMatch(clean, /INTEGRITY:/);

  const flagged = buildImportNotice({
    segmentCount: 3, summaryCount: 0, gapCount: 0, suppressedTotal: 0,
    integritySegments: 2, integrityDelta: -14, recoveredCount: 3, featureStateCount: 2,
  }, 0);
  assert.match(flagged, /INTEGRITY: 2 closed segment\(s\) do not reconcile/);
  assert.match(flagged, /net -14 record\(s\)/);
  assert.match(flagged, /clear last 10 minutes \/ hour \/ day/);
  assert.match(flagged, /3 deleted activity summaries were recovered/);
  assert.match(flagged, /does not make the summary itself primary evidence/);
  assert.match(flagged, /before reading silence for an app as inactivity/);

  const attributed = buildImportNotice({
    segmentCount: 1, summaryCount: 0, gapCount: 0, suppressedTotal: 0,
    identityCount: 12, accountCount: 2, deletedThreadCount: 3,
  }, 0);
  assert.match(attributed, /ATTRIBUTION: 2 ChatGPT accounts have been used/);
  assert.match(attributed, /Only "direct" rows identify an ACCOUNT/);
  assert.match(attributed, /3 Codex conversation\(s\) are marked deleted/);
});

test("streaming sink receives rows and stats instead of a buffered array", async () => {
  const batches = [];
  const out = await extractComputerHistoryDir(FIXTURE_ROOT, {}, {
    onExtractedRows: (batch) => batches.push(batch),
  });
  assert.equal(out.length, 0, "streaming mode returns no buffered rows");
  assert.ok(batches.length > 0);
  assert.ok(batches.flat().some((r) => r.EventKind === "session.started"));
  assert.equal(out._computerHistoryStats.segmentCount, 2);
});
