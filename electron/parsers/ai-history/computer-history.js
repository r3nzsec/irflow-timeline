/**
 * parsers/ai-history/computer-history.js — ChatGPT "Computer History" (Skysight) activity artifacts.
 *
 * Computer History is an opt-in ChatGPT Desktop feature (macOS, off by default) that records an
 * interaction-event stream from the host and periodically distils it into natural-language activity
 * summaries. It is user-activity telemetry, not conversation history — see computer-history-schema.js
 * for why it gets its own column set.
 *
 * Artifacts:
 *   Raw event stream (retained ~48h, then purged):
 *     ~/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/
 *       Library/Caches/ComputerUse/Skysight/segments/<YYYY-MM-DDTHH-MM-SSZ>/events.jsonl
 *       …/<segment>/metadata.json   { startedAt, endedAt, eventCount, suppressedEventCount }
 *
 *   Derived summaries (persist until the user deletes them — often the only survivor on a stale image):
 *     ~/.codex/memories/extensions/skysight/resources/<ts>-<4char>-(10min|6h)-<slug>.md
 *
 *   Feature state (not parsed here; useful corroboration for "was it enabled, and when"):
 *     ~/.codex/config.toml → [plugins."computer-history@openai-bundled"] enabled = true
 *     …/Library/Application Support/Software/ComputerUseAppApprovals.json → belongs to the separate
 *       Computer Use agent feature, NOT the recording scope (see collectFeatureState)
 *
 * Event kinds observed in the live 2026 schema: session.started, session.ended, window.changed,
 * mouse.click, mouse.context_menu, mouse.drag, selection.changed, keyboard.text_input,
 * keyboard.submit, keyboard.shortcut, terminal.value_changed.
 *
 * Notes for the analyst:
 *   - `.id` is a monotonic counter that continues ACROSS segment files but RESTARTS AT 1 on every
 *     recorder session — each session.started carries id 1, and events hold no session identifier,
 *     so the reset is the only run boundary available. It is a join key within a run, never across
 *     the whole capture, and continuity checks must be scoped per run (see detectSegmentGaps).
 *   - Gaps in `.id` are NOT a suppression count. Measured on a live capture: one 10-minute bucket
 *     spanned 2,374 ids while retaining 329 events, against a declared `suppressedEventCount` of 13.
 *     The counter plainly increments for events that are never persisted at all (sub-threshold
 *     movement, filtered apps, coalesced input), which is a different thing from "withheld". Only
 *     `metadata.suppressedEventCount` is authoritative about suppression; id gaps are reported as
 *     "ids not persisted (cause unknown)" and nothing more.
 *   - Segment directories are fixed 10-minute UTC buckets. A missing bucket is NOT by itself a
 *     tamper indicator: if the id chain runs continuously across the hole, the host was simply idle.
 *     `detectSegmentGaps` cross-checks id continuity and only calls out a gap where ids are actually
 *     unaccounted for.
 *   - Capture depth varies by orders of magnitude between apps, tracking the UI toolkit rather than
 *     the app category (see FIDELITY_TIER_BY_BUNDLE and resolveFidelityTier).
 *   - Credential rows are timing anchors, NOT recovered passwords. macOS Secure Input Mode blocks
 *     the recorder's event tap, so the keystrokes consume event ids and are never written — zero
 *     text-bearing input events under secure input across a measured 5,370-event capture.
 *   - `ax.mode` decides how ScreenText must be read: `fullTree` is a screen snapshot,
 *     `diffFromPrevious` is only what changed. 58% of ax-bearing events observed live were diffs.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const { dbg } = require("../../logger");
const { readJsonlBounded } = require("./jsonl-reader");
const { findMemoriesGitDir, findDeletedSummaries, isUsableRepo } = require("./skysight-git-recovery");
const {
  TERMINAL_VALUE_KIND,
  isTerminalValueChanged,
  extractTerminalBuffer,
  describeTerminalActivity,
  terminalBufferNote,
} = require("./computer-history-terminal");
const {
  findIdentityRoot, listAccountPlists, readStatsigStore, readAnalyticsDb,
  readAuthIdentity, readCodexIdentity, readChatgptStatsigServicePlist,
  STRENGTH_DIRECT, STRENGTH_VENDOR, STRENGTH_DEVICE, STRENGTH_TIMELINE,
} = require("./skysight-identity");
const { processFilesConcurrently } = require("./file-batch");
const { tickFileProgress } = require("./extract-plan");
const { formatTimestampUtc, parseIsoTimestamp, truncateSummary } = require("./row-utils");
const {
  TOOL_COMPUTER_HISTORY,
  CLASS_SESSION,
  CLASS_EXECUTION,
  CLASS_WEB,
  CLASS_INPUT,
  CLASS_UI,
  CLASS_DATA_MOVEMENT,
  CLASS_TERMINAL,
  CLASS_NARRATIVE,
  CLASS_CONFIG,
  CLASS_INTEGRITY,
  CLASS_IDENTITY,
  KIND_CLASS,
  APP_CLASS_OVERRIDES,
  FIDELITY_TIER_BY_BUNDLE,
  TIER1_MIN_AX_CHARS,
  TIER2_MIN_AX_CHARS,
  SECURE_TEXT_SUBROLE,
  AX_MODE_DIFF,
  AX_MODE_FULL,
  MAX_CONTENT_CHARS,
  DEFAULT_SCREEN_TEXT_MAX_CHARS,
  ACTIVITY_PREVIEW_LEN,
  SEGMENT_INTERVAL_MS,
} = require("./computer-history-schema");

const CUA_GROUP_DIR_NAME = "2DC432GLL2.com.openai.sky.CUAService";
const SEGMENTS_REL = ["Library", "Caches", "ComputerUse", "Skysight", "segments"];
const SKYSIGHT_RESOURCES_REL = ["memories", "extensions", "skysight", "resources"];
const CODEX_DIR_NAME = ".codex";
const SEGMENT_DIR_RE = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$/;
const SUMMARY_FILE_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})-([A-Za-z0-9]{2,8})-(10min|6h)-(.+)\.md$/i;
const EVENTS_FILE = "events.jsonl";
const METADATA_FILE = "metadata.json";
const MAX_DISCOVERY_DEPTH = 12;
/** Share of the shorter field value that must match for two states to be one composition. */
const TYPING_CONTINUATION_PREFIX_RATIO = 0.7;

/* ------------------------------------------------------------------ helpers */

function capText(text, maxChars) {
  // iTerm2 AX values embed NUL after prompt glyphs. Those bytes are not content, and they
  // make CSV/RFC4180 exports unreadable (`line contains NUL`).
  const value = String(text ?? "").replace(/\u0000/g, "");
  if (value.length <= maxChars) return value;
  const dropped = value.length - maxChars;
  return `${value.slice(0, maxChars)}\n…[truncated ${dropped} chars over ${maxChars}-char cap]`;
}

/** Body of a TOML table, stopping at the next table header. `[^[]*` cannot be used: values like
 *  `args = ["mcp"]` contain `[` and would truncate before `enabled`. */
function tomlTableBody(text, headerPattern) {
  const m = String(text || "").match(headerPattern);
  if (!m) return null;
  const rest = text.slice(m.index + m[0].length);
  const next = rest.search(/\n\[/);
  return next < 0 ? rest : rest.slice(0, next);
}

function firstNonEmpty(...values) {
  for (const v of values) {
    if (v == null) continue;
    const s = typeof v === "string" ? v : String(v);
    if (s.trim() !== "") return s;
  }
  return "";
}

/** `2026-08-14T05-20-00Z` (segment id) / `2026-08-14T05-20-00` (summary prefix) → epoch ms. */
function segmentStampToMs(stamp) {
  if (!stamp) return null;
  const m = String(stamp).match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})Z?$/);
  if (!m) return null;
  return parseIsoTimestamp(`${m[1]}T${m[2]}:${m[3]}:${m[4]}Z`);
}

function msToSegmentId(ms) {
  const iso = new Date(ms).toISOString(); // 2026-08-14T05:20:00.000Z
  return `${iso.slice(0, 13)}-${iso.slice(14, 16)}-${iso.slice(17, 19)}Z`;
}

/* -------------------------------------------------------- path resolution */

function isSegmentDirName(name) {
  return SEGMENT_DIR_RE.test(String(name || ""));
}

/** A `segments/` directory holding at least one `<UTC bucket>/events.jsonl`. */
function isSkysightSegmentsDir(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  let entries;
  try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); } catch { return false; }
  for (const e of entries) {
    if (!e.isDirectory() || !isSegmentDirName(e.name)) continue;
    if (fs.existsSync(path.join(dirPath, e.name, EVENTS_FILE))) return true;
  }
  return false;
}

function isSkysightResourcesDir(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  let entries;
  try { entries = fs.readdirSync(dirPath); } catch { return false; }
  return entries.some((n) => SUMMARY_FILE_RE.test(n));
}

/** True for any directory that contains Computer History evidence somewhere beneath it. */
function isComputerHistoryDir(dirPath) {
  if (!dirPath) return false;
  return !!(findSegmentsDir(dirPath) || findSkysightResourcesDir(dirPath));
}

function isSkysightEventsFile(filePath) {
  if (!filePath) return false;
  if (path.basename(filePath) !== EVENTS_FILE) return false;
  return isSegmentDirName(path.basename(path.dirname(filePath)));
}

function isSkysightSummaryFile(filePath) {
  return !!filePath && SUMMARY_FILE_RE.test(path.basename(filePath));
}

/**
 * Bounded downward search for a directory satisfying `predicate`.
 * Stays inside `rootDir` — a KAPE/triage folder selection must never resolve outside itself.
 */
function findDirBelow(rootDir, predicate, maxDepth = MAX_DISCOVERY_DEPTH) {
  if (!rootDir || !fs.existsSync(rootDir)) return null;
  try {
    if (!fs.statSync(rootDir).isDirectory()) return null;
  } catch { return null; }
  if (predicate(rootDir)) return rootDir;

  const queue = [{ d: rootDir, depth: 0 }];
  while (queue.length) {
    const { d, depth } = queue.shift();
    if (depth >= maxDepth) continue;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink()) continue;
      const child = path.join(d, e.name);
      if (predicate(child)) return child;
      queue.push({ d: child, depth: depth + 1 });
    }
  }
  return null;
}

/**
 * Resolve the raw `segments/` directory from any of:
 *   the segments dir itself · a single segment bucket · an events.jsonl file ·
 *   the CUA group container · a Library/Group Containers root · a KAPE/triage root.
 */
function findSegmentsDir(target) {
  if (!target || !fs.existsSync(target)) return null;

  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }

  // A segment bucket directory — its parent is `segments/`.
  if (isSegmentDirName(path.basename(p)) && isSkysightSegmentsDir(path.dirname(p))) {
    return path.dirname(p);
  }
  if (isSkysightSegmentsDir(p)) return p;

  // Direct hit from a group-container-shaped root.
  const direct = path.join(p, ...SEGMENTS_REL);
  if (isSkysightSegmentsDir(direct)) return direct;

  // Walk up to a CUA group container, then descend the known relative path.
  let up = p;
  for (let i = 0; i < 16; i++) {
    if (path.basename(up) === CUA_GROUP_DIR_NAME) {
      const fromContainer = path.join(up, ...SEGMENTS_REL);
      if (isSkysightSegmentsDir(fromContainer)) return fromContainer;
    }
    const parent = path.dirname(up);
    if (parent === up) break;
    up = parent;
  }

  return findDirBelow(p, isSkysightSegmentsDir);
}

/**
 * Resolve the derived-summary `resources/` directory from a `.codex` root, a memories root,
 * the resources dir itself, a summary file, or a triage root.
 */
function findSkysightResourcesDir(target) {
  if (!target || !fs.existsSync(target)) return null;

  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }

  if (isSkysightResourcesDir(p)) return p;

  const fromCodex = path.join(p, ...SKYSIGHT_RESOURCES_REL);
  if (isSkysightResourcesDir(fromCodex)) return fromCodex;

  let up = p;
  for (let i = 0; i < 16; i++) {
    if (path.basename(up) === CODEX_DIR_NAME) {
      const candidate = path.join(up, ...SKYSIGHT_RESOURCES_REL);
      if (isSkysightResourcesDir(candidate)) return candidate;
    }
    const parent = path.dirname(up);
    if (parent === up) break;
    up = parent;
  }

  return findDirBelow(p, isSkysightResourcesDir);
}

function defaultComputerHistoryRoots() {
  const home = os.homedir();
  return {
    segmentsDir: path.join(home, "Library", "Group Containers", CUA_GROUP_DIR_NAME, ...SEGMENTS_REL),
    resourcesDir: path.join(home, CODEX_DIR_NAME, ...SKYSIGHT_RESOURCES_REL),
  };
}

/* --------------------------------------------------------- classification */

/**
 * What the user DID. Derived from `.kind`, so typing is Input wherever it happens.
 *
 * The app family is deliberately NOT folded in here — it travels in `AppClass` (resolveAppClass).
 * The one exception is `window.changed`, which has no action of its own: a focus row's whole meaning
 * is "the user moved to this app", so there the app family IS the class.
 */
function resolveEventClass(kind, bundleId, url) {
  // Cross-app data movement is the highest-value signal in the stream; never let an app-family
  // override mask it (an iTerm→Slack drag must stay classified as DataMovement, not Terminal).
  if (kind === "mouse.drag") return CLASS_DATA_MOVEMENT;

  if (kind === "window.changed") {
    const override = APP_CLASS_OVERRIDES[bundleId];
    if (override) return override;
    if (url) return CLASS_WEB;
  }

  return KIND_CLASS[kind] || CLASS_EXECUTION;
}

/** WHERE it happened — the app family, orthogonal to the action. Empty for unclassified bundles. */
function resolveAppClass(bundleId, url) {
  const override = APP_CLASS_OVERRIDES[bundleId];
  if (override) return override;
  return url ? CLASS_WEB : "";
}

/**
 * Capture depth for this app: the MORE CAPABLE of the known-app table and what the app actually
 * produced in this capture (lower tier number = deeper capture).
 *
 * Neither input is trustworthy alone, and they fail in opposite directions:
 *
 *   Table only        goes stale. Slack was pinned to Tier 3 ("metadata only") on the reasoning
 *                     that it is a hardened messaging app; it is Electron, and a live capture had
 *                     it exposing 53,590 chars of channel content. Reports built on that entry
 *                     would have claimed only one side of a conversation was recoverable while the
 *                     inbound messages sat in ScreenText.
 *   Measurement only  understates. An app that was on screen briefly produces a small largest-tree
 *                     through lack of opportunity, not lack of capability — Chrome measured 6,814
 *                     chars from a single full-tree capture on the same host. Demoting it would
 *                     tell an analyst not to look for content that the app does in fact expose.
 *
 * Taking the minimum keeps both failure modes safe: a stale table entry can be corrected upward by
 * evidence, and a thin sample can never argue evidence away. Being wrong in this direction costs
 * an analyst a look; being wrong in the other costs them the finding.
 *
 * `axLength` must be the app's LARGEST full-tree capture across the extraction, not one event's —
 * see stampFidelityTiers.
 */
function resolveFidelityTier(bundleId, axLength) {
  const known = FIDELITY_TIER_BY_BUNDLE[bundleId];
  const len = Number(axLength) || 0;
  // No observation at all: fall back to the table, else assume the least capable.
  if (!len) return known || 3;
  const measured = len >= TIER1_MIN_AX_CHARS ? 1 : len >= TIER2_MIN_AX_CHARS ? 2 : 3;
  return known ? Math.min(known, measured) : measured;
}

/**
 * Stamp the per-app tier onto every row, once the whole capture has been seen.
 *
 * Rows leave parseSkysightEvent with a tier only when the bundle is in the measured table. Everything
 * else is resolved here from `axProfile` (bundle → largest observed `fullTree` AX length), so one app
 * gets ONE tier instead of flipping between "deep content" and "metadata only" from row to row
 * depending on whether that particular event happened to carry a full tree.
 */
function stampFidelityTiers(rows, axProfile) {
  const profile = axProfile instanceof Map ? axProfile : new Map();
  const cache = new Map();
  for (const row of rows) {
    // Deliberately NOT skipping rows that already carry a tier. Parse time stamps a provisional
    // value from the table alone (all a streaming sink ever gets); by now the whole capture has
    // been seen, so the measurement is available and may correct it. Skipping here is what let a
    // stale table entry survive contradicting evidence.
    if (!row.BundleId) continue;
    let tier = cache.get(row.BundleId);
    if (tier === undefined) {
      tier = resolveFidelityTier(row.BundleId, profile.get(row.BundleId) || 0);
      cache.set(row.BundleId, tier);
    }
    row.FidelityTier = String(tier);
    row.Description = buildDescription(row);
  }
  return rows;
}

/**
 * Two independent credential signals, and neither recovers a password.
 *
 * `AXSecureTextField` is the focused element's subrole. `app.secureInput` is macOS Secure Input
 * Mode, engaged system-wide whenever any password field holds focus — which is the broader signal:
 * it fires on prompts that expose no secure-field subrole at all (measured live on a third-party
 * app-lock dialog, and on 5 events against the subrole's 2).
 *
 * What Secure Input Mode does is block the event tap this recorder reads from. So the field value
 * is withheld AND the keystrokes are suppressed — they consume event ids and are never written.
 * Measured across a 5,370-event capture: zero keyboard.text_input records carrying text while
 * secure input was engaged. A credential row is a TIMING ANCHOR — a password was entered here, in
 * this app, at this second — and must never be read as a recovered credential.
 *
 * The one value that does surface is the MASKED rendering: selecting a secure field yields a run of
 * U+2022 bullets in selection.selectedText (verified byte-level: 14 and 5 bullets, no other
 * codepoint). It is retained deliberately — its LENGTH is a legitimate corroborating detail — but
 * it is not credential material and must not be quoted as one.
 */
function isCredentialContext(ev, targetSubrole) {
  return targetSubrole === SECURE_TEXT_SUBROLE || ev?.app?.secureInput === true;
}

function describeActivity(kind, ev, bundleId, destBundleId, targetSubrole = "") {
  if (isCredentialContext(ev, targetSubrole)) {
    switch (kind) {
      case "keyboard.submit": return "Credential Submit";
      case "keyboard.text_input": return "Credential Entry";
      // Secure Input engaged while focus lands on a window is the password prompt appearing —
      // often the only row a credential event leaves behind, since the typing never persists.
      case "window.changed": return "Password Prompt";
      case "keyboard.shortcut": return "Shortcut (Secure Input)";
      case "mouse.click": return "Click (Secure Input)";
      case "selection.changed": return "Selection (Secure Input)";
      default: break;
    }
  }

  switch (kind) {
    case "session.started": return "Recording Start";
    case "session.ended": return "Recording Stop";
    case "window.changed":
      if (bundleId === "com.apple.loginwindow") return "Screen Lock";
      return "App Focus";
    // Named by what the multiplicity MEANS, not by its number. `Click (x2)`…`Click (x10)` put a
    // numeric dimension into a categorical column: ten Activity values for one action, so "show me
    // every click" needed ten checkboxes or a regex, and stacking Activity was dominated by noise.
    // The exact count is not lost — it already has its own column (ClickCount), which is where a
    // numeric dimension belongs. macOS keeps incrementing clickCount while clicks stay inside the
    // double-click interval, so anything past a triple-click is one behaviour: rapid repetition.
    case "mouse.click": {
      const count = Number(ev?.mouse?.clickCount) || 0;
      if (count >= 4) return "Multi-Click";      // rapid repeated clicking (impatience, spam, stuck UI)
      if (count === 3) return "Triple-Click";    // select line / paragraph
      if (count === 2) return "Double-Click";    // open / launch / select word — a distinct intent
      return "Click";
    }
    case "mouse.context_menu": return "Context Menu";
    case "mouse.drag":
      return destBundleId && bundleId && destBundleId !== bundleId ? "Cross-App Drag" : "Drag";
    case "selection.changed":
      return Array.isArray(ev?.selection?.selectedItems) && ev.selection.selectedItems.length
        ? "Item Selection"
        : "Selection";
    case "keyboard.text_input": return "Text Input";
    case "keyboard.submit": return "Submit";
    case "keyboard.shortcut": return "Shortcut";
    case "terminal.value_changed": return describeTerminalActivity(ev);
    default: return kind ? kind.replace(/[._]/g, " ") : "Event";
  }
}

function buildDescription(row) {
  const preview = truncateSummary(row.Content || row.WindowTitle || "").slice(0, ACTIVITY_PREVIEW_LEN);
  const where = row.AppName || row.BundleId || "—";
  const win = row.WindowTitle ? ` | Window: ${row.WindowTitle}` : "";
  const url = row.Url ? ` | URL: ${row.Url}` : "";
  const target = row.TargetRole
    ? ` | Target: ${row.TargetRole}${row.TargetSubrole ? `/${row.TargetSubrole}` : ""}`
      + `${row.TargetLabel ? ` "${row.TargetLabel}"` : ""}`
    : "";
  const items = row.SelectedItemCount && row.SelectedItemCount !== "0"
    ? ` | Selected ${row.SelectedItemCount}: ${truncateSummary(row.SelectedItems).slice(0, ACTIVITY_PREVIEW_LEN)}`
    : "";
  const dest = row.DestAppName ? ` | → ${row.DestAppName}${row.DestWindowTitle ? ` (${row.DestWindowTitle})` : ""}` : "";
  const chord = row.KeyChord ? ` | Keys: ${row.KeyChord}` : "";
  const tier = row.FidelityTier ? ` | Tier: ${row.FidelityTier}` : "";
  // ScreenText from a diff capture is NOT a screen snapshot. Say so on the row itself, so the
  // qualification survives CSV export and report copy-paste rather than living only in AxMode.
  const ax = row.ScreenText && row.AxMode === AX_MODE_DIFF
    ? " | ScreenText: CHANGES ONLY (ax.mode=diffFromPrevious — not a full screen capture)"
    : "";
  // Carried on Activity as well as the subrole, because Secure Input Mode fires on prompts that
  // expose no secure-field subrole — and because this qualification must survive CSV export and
  // report copy-paste rather than living only in a column an analyst may have hidden.
  const secure = row.TargetSubrole === SECURE_TEXT_SUBROLE || /Credential |Secure Input|Password Prompt/.test(row.Activity || "")
    ? " | SECURE INPUT: macOS withheld the field value AND suppressed the keystrokes — this row"
      + " evidences THAT a password was entered here, not what it was"
    : "";
  const seg = row.SegmentId ? ` | Segment: ${row.SegmentId}` : "";
  const body = preview ? ` - "${preview}"` : "";
  return `[${row.Timestamp}] ${row.Activity} in ${where}${body}${win}${url}${target}${items}${dest}`
    + `${chord}${secure}${ax}${tier}${seg}`;
}

/* ------------------------------------------------------------ row builder */

function makeComputerHistoryRow(fields) {
  const content = capText(fields.content, MAX_CONTENT_CHARS);
  const row = {
    Timestamp: fields.timestamp || "",
    EventClass: fields.eventClass || "",
    AppClass: fields.appClass || "",
    EventKind: fields.eventKind || "",
    Activity: fields.activity || "",
    AppName: fields.appName || "",
    BundleId: fields.bundleId || "",
    WindowTitle: fields.windowTitle || "",
    Url: fields.url || "",
    TargetRole: fields.targetRole || "",
    TargetSubrole: fields.targetSubrole || "",
    TargetLabel: fields.targetLabel || "",
    TargetDescription: fields.targetDescription || "",
    TargetId: fields.targetId || "",
    Content: content,
    // Length of the ORIGINAL payload, before the retention cap — so a truncated row still reports
    // how much text actually existed on disk.
    ContentLength: fields.contentLength != null
      ? String(fields.contentLength)
      : String(String(fields.content ?? "").length),
    // The keystrokes carried by THIS event. Content holds the cumulative field value, which cannot
    // reconstruct a mid-field edit — observed live in 121 of 276 cases, where the cumulative value
    // does not end with the delta (a paste-over, a cursor jump, an insertion mid-string).
    TypedDelta: fields.typedDelta || "",
    KeyChord: fields.keyChord || "",
    MouseButton: fields.mouseButton || "",
    ClickCount: fields.clickCount != null && fields.clickCount !== "" ? String(fields.clickCount) : "",
    SelectionOffset: fields.selectionOffset != null ? String(fields.selectionOffset) : "",
    SelectionLength: fields.selectionLength != null ? String(fields.selectionLength) : "",
    SelectedItems: fields.selectedItems || "",
    SelectedItemRoles: fields.selectedItemRoles || "",
    SelectedItemCount: fields.selectedItemCount ? String(fields.selectedItemCount) : "",
    DestAppName: fields.destAppName || "",
    DestBundleId: fields.destBundleId || "",
    DestWindowTitle: fields.destWindowTitle || "",
    DestUrl: fields.destUrl || "",
    DestTargetRole: fields.destTargetRole || "",
    DestTargetSubrole: fields.destTargetSubrole || "",
    // What the drag actually landed on, and what was there. Origin-only capture answers "what was
    // taken" but not "where it went" — the receiving end of the data movement.
    DestTargetLabel: fields.destTargetLabel || "",
    DestContent: capText(fields.destContent ?? "", MAX_CONTENT_CHARS),
    FidelityTier: fields.fidelityTier != null ? String(fields.fidelityTier) : "",
    AxMode: fields.axMode || "",
    AxLength: fields.axLength != null ? String(fields.axLength) : "",
    ScreenText: fields.screenText || "",
    EventId: fields.eventId != null && fields.eventId !== "" ? String(fields.eventId) : "",
    SegmentId: fields.segmentId || "",
    SegmentStart: fields.segmentStart || "",
    SegmentEnd: fields.segmentEnd || "",
    SegmentSuppressed: fields.segmentSuppressed != null ? String(fields.segmentSuppressed) : "",
    SegmentEventCount: fields.segmentEventCount != null ? String(fields.segmentEventCount) : "",
    SegmentCountDelta: fields.segmentCountDelta != null ? String(fields.segmentCountDelta) : "",
    SummarySuggestion: fields.summarySuggestion || "",
    SummaryCitations: fields.summaryCitations || "",
    Identifier: fields.identifier || "",
    SourceFile: fields.sourceFile || "",
    RecordedSourcePath: fields.recordedSourcePath || "",
    LineNumber: fields.lineNumber != null && fields.lineNumber !== "" ? String(fields.lineNumber) : "",
    User: fields.user || "",
    Host: fields.host || "",
    Description: "",
    RecordId: "",
  };
  row.Description = buildDescription(row);
  return row;
}

/* --------------------------------------------------------- event parsing */

/**
 * Convert one Skysight interaction event into a timeline row.
 * Returns null for records without a usable timestamp (never fabricate one).
 */
function parseSkysightEvent(ev, sourceFile, ctx = {}, attribution = {}, options = {}) {
  if (!ev || typeof ev !== "object") return null;
  const kind = String(ev.kind || "").trim();
  if (!kind) return null;

  const ms = parseIsoTimestamp(ev.timestamp);
  if (ms == null) return null;

  const app = ev.app || ev.mouse?.origin?.app || null;
  const bundleId = firstNonEmpty(app?.bundleIdentifier);
  const appName = firstNonEmpty(app?.name);

  const windowTitle = firstNonEmpty(ev.window?.title, ev.mouse?.origin?.window?.title);
  const url = firstNonEmpty(ev.window?.url, ev.mouse?.origin?.window?.url);

  const target = ev.keyboard?.target || ev.mouse?.target || ev.selection?.target
    || ev.mouse?.origin?.element || null;
  const targetRole = firstNonEmpty(target?.role);
  const targetSubrole = firstNonEmpty(target?.subrole);
  const targetLabel = firstNonEmpty(target?.title, target?.description, target?.placeholder);
  // description is the accessible label, title the visible one. They are different facts, not
  // fallbacks: 277 observed events carried both, and the description was silently lost.
  const targetDescription = firstNonEmpty(target?.description);
  const targetId = firstNonEmpty(target?.identifier);

  // Selected UI items — Finder rows (which files were picked) and menu commands. These events
  // frequently carry NO selectedText, so without this they land as rows with an empty payload.
  const selectedItems = Array.isArray(ev.selection?.selectedItems) ? ev.selection.selectedItems : [];
  const selectedItemTitles = selectedItems
    .map((it) => firstNonEmpty(it?.title, it?.description, it?.value, it?.identifier))
    .filter(Boolean)
    .join(" | ");
  const selectedItemRoles = selectedItems
    .map((it) => firstNonEmpty(it?.subrole, it?.role))
    .filter(Boolean)
    .join(", ");

  const keyboardText = firstNonEmpty(ev.keyboard?.text);

  let content = "";
  switch (kind) {
    case "keyboard.text_input":
    case "keyboard.submit":
      // `target.value` is the CUMULATIVE field state; `text` is only the latest keystroke group.
      content = firstNonEmpty(ev.keyboard?.target?.value, ev.keyboard?.text);
      break;
    case "keyboard.shortcut":
      content = firstNonEmpty(ev.keyboard?.target?.value);
      break;
    case "selection.changed":
      // Text selection first; fall back to the selected items so a Finder/menu selection is not
      // recorded as an empty row.
      content = firstNonEmpty(ev.selection?.selectedText, selectedItemTitles);
      break;
    case "mouse.click":
    case "mouse.context_menu":
      content = firstNonEmpty(ev.mouse?.target?.title, ev.mouse?.target?.value, ev.mouse?.target?.description);
      break;
    case "mouse.drag":
      content = firstNonEmpty(ev.mouse?.origin?.element?.value, ev.mouse?.origin?.element?.title);
      break;
    case "terminal.value_changed":
      content = extractTerminalBuffer(ev).content;
      break;
    default:
      content = "";
  }

  // `mouse.modifiers` was dropped entirely. It is the modifier held during a click or drag, and it
  // changes what the click MEANT: command-click on an AXLink opens the link in a background tab
  // (deliberately not navigating away — the bulk-open / harvest pattern), shift-click extends a
  // range selection, command-click on a row multi-selects. Observed live on Edge, Prisma Browser
  // and an Electron file list. Both vocabularies are the same words ("command", "shift",
  // "control", "function"), so they share KeyChord rather than needing a column of their own.
  const modifiers = [
    ...(Array.isArray(ev.keyboard?.modifiers) ? ev.keyboard.modifiers : []),
    ...(Array.isArray(ev.mouse?.modifiers) ? ev.mouse.modifiers : []),
  ];
  const keyEquivalent = firstNonEmpty(ev.keyboard?.keyEquivalent);
  const keyChord = [...modifiers, keyEquivalent].filter(Boolean).join("+");

  const destApp = ev.mouse?.destination?.app || null;
  const destBundleId = firstNonEmpty(destApp?.bundleIdentifier);
  const destElement = ev.mouse?.destination?.element || null;

  const axText = typeof ev.ax?.text === "string" ? ev.ax.text : "";
  const axMode = firstNonEmpty(ev.ax?.mode);
  const axLength = axText.length;
  // Fidelity is per-app, so only a full-tree capture tells us what this app can expose. Record it
  // against the bundle; the tier itself is stamped once the whole capture has been seen.
  if (options.axProfile instanceof Map && bundleId && axMode === AX_MODE_FULL) {
    const prev = options.axProfile.get(bundleId) || 0;
    if (axLength > prev) options.axProfile.set(bundleId, axLength);
  }
  const includeScreenText = options.includeScreenText !== false;
  const screenTextMax = Number(options.screenTextMaxChars) > 0
    ? Number(options.screenTextMaxChars)
    : DEFAULT_SCREEN_TEXT_MAX_CHARS;

  const row = makeComputerHistoryRow({
    timestamp: formatTimestampUtc(ms),
    eventClass: resolveEventClass(kind, bundleId, url),
    appClass: resolveAppClass(bundleId, url),
    eventKind: kind,
    activity: describeActivity(kind, ev, bundleId, destBundleId, targetSubrole),
    appName,
    bundleId,
    windowTitle,
    url,
    targetRole,
    targetSubrole,
    targetLabel,
    targetDescription,
    targetId,
    content,
    // Only worth keeping when it is not simply the tail of the cumulative value.
    typedDelta: keyboardText && !String(content).endsWith(keyboardText) ? keyboardText : "",
    keyChord,
    mouseButton: firstNonEmpty(ev.mouse?.button),
    clickCount: ev.mouse?.clickCount,
    selectionOffset: ev.selection?.selectedRange?.location,
    selectionLength: ev.selection?.selectedRange?.length,
    selectedItems: selectedItemTitles,
    selectedItemRoles,
    selectedItemCount: selectedItems.length,
    destAppName: firstNonEmpty(destApp?.name),
    destBundleId,
    destWindowTitle: firstNonEmpty(ev.mouse?.destination?.window?.title),
    destUrl: firstNonEmpty(ev.mouse?.destination?.window?.url),
    destTargetRole: firstNonEmpty(destElement?.role),
    destTargetSubrole: firstNonEmpty(destElement?.subrole),
    destTargetLabel: firstNonEmpty(destElement?.title, destElement?.description),
    destContent: firstNonEmpty(destElement?.value),
    // Provisional: a bundle absent from the measured table is tiered from the whole capture at
    // finalization (stampFidelityTiers), not from this one event's AX volume.
    fidelityTier: FIDELITY_TIER_BY_BUNDLE[bundleId] || "",
    axMode,
    axLength,
    screenText: includeScreenText && axText ? capText(axText, screenTextMax) : "",
    eventId: ev.id,
    segmentId: ctx.segmentId || "",
    segmentStart: ctx.segmentStart || "",
    segmentEnd: ctx.segmentEnd || "",
    segmentSuppressed: ctx.segmentSuppressed,
    segmentEventCount: ctx.segmentEventCount,
    sourceFile: sourceFile || "",
    recordedSourcePath: ctx.recordedSourcePath || "",
    user: attribution.user || "",
    host: attribution.host || "",
  });
  if (isTerminalValueChanged(kind)) {
    for (const note of terminalBufferNote(ev)) {
      row.Description += ` | ${note}`;
    }
  }
  return row;
}

/* ------------------------------------------------------------- coalescing */

function typedRunKey(row) {
  return [row.BundleId, row.WindowTitle, row.TargetRole, row.TargetLabel].join("\x1f");
}

/** A scrollback buffer wide enough that consecutive values are screen states, not a composition. */
const SCROLLBACK_MIN_CHARS = 2000;

/**
 * True when a row's payload is a terminal screen buffer rather than a field the user is composing.
 *
 * Recognised two ways: the app is a known terminal family (AppClass), or — for an emulator absent
 * from that table, e.g. Ghostty/Alacritty/Tabby — the payload has the structural shape of one, a
 * large AXTextArea value. Without the second test an unlisted terminal would be coalesced and its
 * whole command/output timeline would collapse into a single row.
 */
function isScrollbackSnapshot(row) {
  if (row.EventKind === TERMINAL_VALUE_KIND) return true;
  if (row.AppClass === CLASS_TERMINAL) return true;
  return row.TargetRole === "AXTextArea" && (row.Content || "").length >= SCROLLBACK_MIN_CHARS;
}

function commonPrefixLength(a, b) {
  const max = Math.min(a.length, b.length);
  let i = 0;
  while (i < max && a.charCodeAt(i) === b.charCodeAt(i)) i += 1;
  return i;
}

/**
 * True when `next` continues the composition in `prev` — forward typing (prev is a prefix of next)
 * or backspacing (next is a prefix of prev).
 *
 * Skysight does NOT emit an event for every intermediate field state, so a multi-character
 * correction breaks a strict prefix chain. Observed live: "…what are the evnt" → delete →
 * "…what are the evn" → "…what are the events and apps…". "evn" is not a prefix of "events", yet
 * this is plainly one composition. A shared prefix covering most of the shorter value is therefore
 * accepted as a continuation; an unrelated value (a cleared and retyped field) is not.
 */
function isTypingContinuation(prev, next) {
  if (prev === "") return true;
  if (next.startsWith(prev) || prev.startsWith(next)) return true;
  const min = Math.min(prev.length, next.length);
  if (min === 0) return false;
  return commonPrefixLength(prev, next) >= min * TYPING_CONTINUATION_PREFIX_RATIO;
}

/**
 * Collapse a per-keystroke `keyboard.text_input` run into the completed field value.
 *
 * Skysight emits one text_input event per keystroke group, each carrying the cumulative
 * `target.value`. Raw, a two-sentence prompt becomes ~40 rows whose Content is a growing prefix of
 * the same string.
 *
 * Runs are tracked PER FIELD and survive interleaving. In real captures a composition is routinely
 * interrupted by selection.changed, keyboard.shortcut, mouse.click (model pickers, autocomplete) and
 * even focus changes to another app and back — on one live 13-minute sample, 489 of 798 rows were
 * interleaved selection/shortcut noise. Flushing on any foreign event would leave the prompt split
 * into fragments, so a run only ends when: the same field receives a value that is not a
 * continuation (see isTypingContinuation), the field is submitted, or input ends.
 *
 * The retained row keeps the LAST event's timestamp/EventId — the moment the text was complete —
 * and records the run's start and event count in Description so the typing span stays auditable.
 * Original row order is preserved. Pass `{ coalesceTypedInput: false }` to keep every keystroke row.
 */
function coalesceTypedInput(rows) {
  const pending = new Map(); // fieldKey -> { idx, value, count, firstTimestamp, firstEventId }
  const drop = new Set();

  const close = (key) => {
    const run = pending.get(key);
    pending.delete(key);
    if (!run || run.count < 2) return;
    const kept = rows[run.idx];
    kept.Description += ` | Coalesced ${run.count} keystroke events from ${run.firstTimestamp}`
      + `${run.firstEventId && kept.EventId ? ` (id ${run.firstEventId}–${kept.EventId})` : ""}`;
  };

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const kind = row.EventKind;
    if (kind !== "keyboard.text_input" && kind !== "keyboard.submit" && kind !== "keyboard.shortcut") {
      continue;
    }
    // Terminal emulators expose the WHOLE visible scrollback buffer as the AXTextArea value, so
    // successive rows are screen-state snapshots, not an evolving user composition. They share a
    // long common prefix and would collapse into a single row, destroying the command/output
    // timeline — the most valuable content in the stream. Never coalesce them.
    if (isScrollbackSnapshot(row)) continue;

    const key = typedRunKey(row);
    if (kind === "keyboard.submit") {
      // Submitting ends the composition; a later value in the same field is a NEW prompt.
      close(key);
      continue;
    }

    if (kind === "keyboard.shortcut") {
      // Editing shortcuts (delete, paste, …) mutate the field between text_input events and carry
      // the intermediate value. Without following them a typo correction breaks the prefix chain —
      // observed live: "…the evnt" → delete → "…the evn" → "…the events and…". The shortcut row is
      // independent evidence, so it is only read here, never counted into the run or dropped.
      const active = pending.get(key);
      if (active && row.Content) active.value = row.Content;
      continue;
    }

    const run = pending.get(key);
    if (run && isTypingContinuation(run.value, row.Content)) {
      drop.add(run.idx);
      run.idx = i;
      run.value = row.Content;
      run.count += 1;
      continue;
    }
    close(key);
    pending.set(key, {
      idx: i, value: row.Content, count: 1,
      firstTimestamp: row.Timestamp, firstEventId: row.EventId,
    });
  }
  for (const key of [...pending.keys()]) close(key);

  return drop.size ? rows.filter((_, i) => !drop.has(i)) : rows;
}

/* --------------------------------------------------------- segment access */

function readSegmentMetadata(segmentDir) {
  const metaPath = path.join(segmentDir, METADATA_FILE);
  const out = {
    startedAt: "",
    endedAt: "",
    eventCount: null,
    suppressedEventCount: null,
    open: true,
    // `eventsPath` is the absolute path the recorder wrote at capture time. On a KAPE/triage copy it
    // is the only in-artifact proof of the original home directory, user and volume — the on-disk
    // location tells you where the evidence sits now, this tells you where it came from.
    recordedEventsPath: "",
    recordedId: "",
  };
  let raw;
  try { raw = fs.readFileSync(metaPath, "utf8"); } catch { return out; }
  let meta;
  try { meta = JSON.parse(raw); } catch { return out; }
  if (!meta || typeof meta !== "object") return out;

  out.recordedEventsPath = typeof meta.eventsPath === "string" ? meta.eventsPath : "";
  out.recordedId = typeof meta.id === "string" ? meta.id : "";

  const startMs = parseIsoTimestamp(meta.startedAt);
  const endMs = parseIsoTimestamp(meta.endedAt);
  out.startedAt = startMs != null ? formatTimestampUtc(startMs) : "";
  out.endedAt = endMs != null ? formatTimestampUtc(endMs) : "";
  out.eventCount = Number.isFinite(meta.eventCount) ? meta.eventCount : null;
  out.suppressedEventCount = Number.isFinite(meta.suppressedEventCount) ? meta.suppressedEventCount : null;
  // `endedAt: null` means the bucket is still being written — its hash is provisional.
  out.open = meta.endedAt == null;
  return out;
}

function listSegmentDirs(segmentsDir) {
  let entries;
  try { entries = fs.readdirSync(segmentsDir, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((e) => e.isDirectory() && !e.isSymbolicLink() && isSegmentDirName(e.name))
    .map((e) => path.join(segmentsDir, e.name))
    .filter((d) => fs.existsSync(path.join(d, EVENTS_FILE)))
    .sort();
}

/**
 * Derive rows for 10-minute buckets missing between the first and last observed segment.
 *
 * These rows are SYNTHETIC — they assert an absence, not an observation — and are labelled as such
 * (`EventKind: "segment.gap"`). Disable with `{ detectGaps: false }`.
 *
 * A missing bucket on its own says nothing about tampering. `.id` continues across buckets, so it
 * decides between the two readings: if the last id before the hole and the first id after it are
 * consecutive, no event was lost and the host was simply idle (observed live: bucket 06-30 absent,
 * ids running 6347 → 6348 straight through). Only a discontinuity means events are unaccounted for.
 *
 * CRITICAL: `.id` is monotonic only WITHIN a recorder session. It restarts at 1 every time the
 * recorder does — each `session.started` event carries `id: 1`, and events carry no session
 * identifier, so the reset is the only run boundary there is. One 35-hour capture held four runs,
 * the counter reaching 17,169 before dropping back to 1.
 *
 * Comparing ids across such a boundary is meaningless, and the failure is not benign: the naive
 * subtraction yields a negative "missing" count, which reads as "<= 0" and therefore as the
 * REASSURING branch. On that capture it emitted "ids run continuously (17169 → 1), so no events
 * are missing" for 183 of 186 gap rows — clearing thirteen-hour holes it had never assessed. A
 * check that cannot answer must say so, not answer "fine".
 *
 * `idRanges` maps segment id → {min, max, sessionStart}; without it the gap is reported as
 * unassessed rather than as a finding.
 */
function detectSegmentGaps(segmentIds, segmentsDir, attribution = {}, idRanges = null) {
  const stamps = segmentIds
    .map((id) => ({ id, ms: segmentStampToMs(id) }))
    .filter((s) => s.ms != null)
    .sort((a, b) => a.ms - b.ms);
  if (stamps.length < 2) return [];

  const present = new Set(stamps.map((s) => s.id));
  const rangeFor = (id) => (idRanges instanceof Map ? idRanges.get(id) : idRanges?.[id]) || null;

  /** Nearest observed bucket before/after `ms` that actually reported an id range. */
  const neighbourRanges = (ms) => {
    let before = null;
    let after = null;
    for (const s of stamps) {
      const r = rangeFor(s.id);
      if (!r || !Number.isFinite(r.max) || !Number.isFinite(r.min)) continue;
      if (s.ms < ms) before = r;
      else if (s.ms > ms && !after) after = r;
    }
    return { before, after };
  };

  const rows = [];
  for (let t = stamps[0].ms; t < stamps[stamps.length - 1].ms; t += SEGMENT_INTERVAL_MS) {
    const id = msToSegmentId(t);
    if (present.has(id)) continue;

    const { before, after } = neighbourRanges(t);
    let activity = "Segment Gap (unassessed)";
    let verdict = "Event-id continuity was not evaluated, so this gap is neither confirmed nor "
      + "cleared as evidence loss.";

    if (before && after) {
      // The recorder restarted somewhere in this hole: the counter is back at or below where it
      // already was, or the next bucket opens with a session.started. Either way the two ids are
      // from different runs and cannot be subtracted.
      const restarted = after.sessionStart === true || after.min <= before.max;
      if (restarted) {
        activity = "Segment Gap (recorder restarted — unassessed)";
        verdict = `The event-id counter restarts at 1 with each recorder session, and it reset `
          + `across this bucket (${before.max} → ${after.min}). Ids from different runs cannot be `
          + "compared, so continuity CANNOT assess whether events were deleted here — this gap is "
          + "neither confirmed nor cleared. Corroborate against metadata suppressedEventCount, the "
          + "summaries, and system logs for the restart itself.";
      } else {
        const missing = after.min - before.max - 1;
        if (missing <= 0) {
          activity = "Segment Gap (no activity)";
          verdict = `Event ids run continuously across this bucket (${before.max} → ${after.min}), `
            + "so no events are missing. The host was idle, asleep, or recording was paused — this "
            + "is NOT evidence of deletion.";
        } else {
          activity = "Segment Gap (ids unaccounted for)";
          verdict = `${missing} event id(s) are unaccounted for across this bucket `
            + `(${before.max} → ${after.min}). Ids are not a suppression count — the counter also `
            + "advances for events that are never persisted — so this is a lead to corroborate "
            + "against metadata suppressedEventCount, not a finding of deletion.";
        }
      }
    }

    rows.push(makeComputerHistoryRow({
      timestamp: formatTimestampUtc(t),
      eventClass: CLASS_SESSION,
      eventKind: "segment.gap",
      activity,
      content: `No segment directory for the 10-minute bucket ${id}. ${verdict} `
        + "Derived from the bucket sequence — not an observed event.",
      segmentId: id,
      segmentStart: formatTimestampUtc(t),
      segmentEnd: formatTimestampUtc(t + SEGMENT_INTERVAL_MS),
      sourceFile: segmentsDir,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/* --------------------------------------------------- derived summary (.md) */

/** Minimal frontmatter reader — the summaries use a small, fixed YAML subset. No YAML dependency. */
function parseSummaryFrontmatter(text) {
  const out = { fields: {}, nested: {}, body: String(text || "") };
  const m = out.body.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!m) return out;
  out.body = out.body.slice(m[0].length);

  const unquote = (v) => v.replace(/^["']|["']$/g, "");
  const inlineList = (v) => (v.startsWith("[") && v.endsWith("]")
    ? v.slice(1, -1).split(",").map((s) => s.trim()).filter(Boolean).join(", ")
    : v);

  // One level of nesting is enough for the observed shape: scalars at the root plus a `suggestion:`
  // block whose children are the "suggested skill or automation" the docs list as a timeline field.
  let parent = null;
  for (const line of m[1].split(/\r?\n/)) {
    if (!line.trim()) continue;
    const indented = /^\s+\S/.test(line);
    const kv = line.trim().match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!kv) continue;
    const key = kv[1];
    const value = unquote(inlineList(kv[2].trim()));

    if (indented && parent) {
      if (!out.nested[parent]) out.nested[parent] = {};
      out.nested[parent][key] = value;
      continue;
    }
    if (value === "") { parent = key; out.fields[key] = ""; continue; }
    parent = null;
    out.fields[key] = value;
  }
  return out;
}

/**
 * Pull the trailing `## Citations` list out of a summary body.
 *
 * Each summary ends with the absolute paths of the events.jsonl/metadata.json it was derived from,
 * plus links to the summaries it built on. That is the bridge from LLM narrative back to primary
 * evidence — the thing that lets an analyst verify a claim — and the paths are recorded ones, so
 * they also carry original-host provenance on a triage copy.
 */
function extractSummaryCitations(body) {
  const m = String(body || "").match(/^#{1,4}\s*Citations\s*$([\s\S]*)$/mi);
  if (!m) return "";
  const lines = [];
  for (const raw of m[1].split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (/^#{1,4}\s/.test(line)) break; // next section
    lines.push(line.replace(/^[-*]\s*/, ""));
  }
  return lines.join("\n");
}

/** Body text under a `##`/`###` heading, up to the next heading of any level. */
function extractSummarySection(body, heading) {
  const re = new RegExp(`^#{2,4}\\s*${heading.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*$`, "mi");
  const m = String(body || "").match(re);
  if (!m) return "";
  const rest = String(body).slice(m.index + m[0].length);
  const next = rest.search(/^#{1,4}\s/m);
  return (next === -1 ? rest : rest.slice(0, next)).trim();
}

/**
 * The distinct assertions buried inside one summary body.
 *
 * A summary file is not one statement. It has structurally different halves that were being
 * flattened into a single ScreenText blob, where none of them could be filtered, searched or
 * tagged separately — and where an analyst scanning the grid would never learn they existed:
 *
 *   Recording summary   what happened inside this window. Bounded by the window. ~415 chars.
 *   Relevant prior context   carried in from EARLIER windows. This is the trap: the row's
 *                       timestamp does NOT bound the information in it. ~415 chars.
 *   Important non-obvious context about the user   the largest section at ~1,015 chars, and the
 *                       highest-value one: a model-written dossier naming documents, typed search
 *                       terms, org and project names, and what each app was being used for. It
 *                       survives the 48h raw purge, so on a stale image it may be the only place a
 *                       search term the user typed still exists.
 *
 * Each becomes its own row so it can be found. The parent row still carries the whole body, so
 * nothing is lost and the sub-rows are additive.
 */
const SUMMARY_SECTIONS = [
  {
    heading: "Relevant prior context",
    kind: "summary.priorcontext",
    activity: "Prior Context (carried from earlier windows)",
    caveat: "CARRIED FORWARD: this text summarises activity from BEFORE this window. The row "
      + "timestamp is the window it was written in, NOT the time of the activity it describes.",
  },
  {
    heading: "Important non-obvious context about the user",
    kind: "summary.profile",
    activity: "User Profile (model-inferred)",
    caveat: "MODEL-INFERRED PROFILE: entities, documents, search terms and app roles the "
      + "summariser attributed to the user. It persists after the ~48h raw purge, so it may name "
      + "evidence whose primary record is already gone — corroborate before relying on it.",
  },
];

function listSummaryFiles(resourcesDir) {
  let entries;
  try { entries = fs.readdirSync(resourcesDir, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((e) => e.isFile() && SUMMARY_FILE_RE.test(e.name))
    .map((e) => path.join(resourcesDir, e.name))
    .sort();
}

/**
 * Parse one derived activity summary. These outlive the ~48h raw-event purge, so on a stale image
 * they are often the only surviving record — but they are LLM-generated interpretation, and the
 * generator self-redacts (observed: "contents contained personal/order details and are omitted
 * here"). Treat as corroboration, never as primary evidence when the raw stream is available.
 */
function parseSummaryFile(filePath, attribution = {}, options = {}) {
  const base = path.basename(filePath);
  const m = base.match(SUMMARY_FILE_RE);
  if (!m) return null;
  const ms = segmentStampToMs(m[1]);
  if (ms == null) return null;

  let text;
  try { text = fs.readFileSync(filePath, "utf8"); } catch { return null; }

  const { fields, nested, body } = parseSummaryFrontmatter(text);
  const window = m[3].toLowerCase();
  const screenTextMax = Number(options.screenTextMaxChars) > 0
    ? Number(options.screenTextMaxChars)
    : DEFAULT_SCREEN_TEXT_MAX_CHARS;

  const suggestion = nested.suggestion || {};
  const suggestionText = [
    suggestion.type ? `[${suggestion.type}]` : "",
    suggestion.name || "",
    suggestion.description || "",
  ].filter(Boolean).join(" ");

  return makeComputerHistoryRow({
    timestamp: formatTimestampUtc(ms),
    eventClass: CLASS_NARRATIVE,
    eventKind: `summary.${window}`,
    activity: `Activity Summary (${window})`,
    appName: fields.applications || "",
    targetRole: "SkysightSummary",
    targetLabel: fields.title || "",
    content: firstNonEmpty(fields.description, truncateSummary(body)),
    summarySuggestion: suggestionText,
    summaryCitations: extractSummaryCitations(body),
    screenText: capText(body.trim(), screenTextMax),
    axLength: body.trim().length,
    fidelityTier: "",
    segmentId: `${m[1]}Z`,
    segmentStart: formatTimestampUtc(ms),
    segmentEnd: formatTimestampUtc(ms + (window === "6h" ? 6 * 60 * 60 * 1000 : SEGMENT_INTERVAL_MS)),
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

/**
 * One summary file as the rows it actually contains: the activity summary, plus a row per distinct
 * assertion inside its body (see SUMMARY_SECTIONS).
 *
 * The caveat lands on Description rather than Content so that Content stays clean for search,
 * secret scanning and export, while the qualification still travels with the row into a CSV or a
 * pasted report — the same split used for the Secure Input and diff-capture warnings.
 */
function parseSummaryFileRows(filePath, attribution = {}, options = {}) {
  const parent = parseSummaryFile(filePath, attribution, options);
  if (!parent) return [];
  const rows = [parent];

  let text = "";
  try { text = fs.readFileSync(filePath, "utf8"); } catch { return rows; }
  const { body } = parseSummaryFrontmatter(text);

  for (const sec of SUMMARY_SECTIONS) {
    const content = extractSummarySection(body, sec.heading);
    if (!content) continue;
    const row = makeComputerHistoryRow({
      timestamp: parent.Timestamp,
      eventClass: CLASS_NARRATIVE,
      eventKind: sec.kind,
      activity: sec.activity,
      appName: parent.AppName,
      targetRole: "SkysightSummary",
      targetLabel: parent.TargetLabel,
      content,
      summaryCitations: parent.SummaryCitations,
      fidelityTier: "",
      segmentId: parent.SegmentId,
      segmentStart: parent.SegmentStart,
      segmentEnd: parent.SegmentEnd,
      sourceFile: filePath,
      recordedSourcePath: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    });
    row.Description += ` | ${sec.caveat}`;
    rows.push(row);
  }
  return rows;
}

/**
 * Recover summaries the user cleared, from the memories git repository.
 *
 * Rows are labelled `summary.deleted` and carry the deleting commit's timestamp in Content — the
 * row's own Timestamp stays the summary's activity window so it sorts into the timeline where the
 * activity happened, not where the deletion happened.
 */
async function recoverDeletedSummaries(resourcesDir, attribution = {}, options = {}) {
  const gitDir = findMemoriesGitDir(resourcesDir);
  if (!gitDir || !(await isUsableRepo(gitDir))) return [];

  let deleted;
  try {
    deleted = await findDeletedSummaries(gitDir, {});
  } catch (e) {
    dbg("AIHIST", "skysight recovery failed", { gitDir, err: e.message });
    return [];
  }

  const screenTextMax = Number(options.screenTextMaxChars) > 0
    ? Number(options.screenTextMaxChars)
    : DEFAULT_SCREEN_TEXT_MAX_CHARS;

  const rows = [];
  for (const item of deleted) {
    const base = path.basename(item.filePath);
    const m = base.match(SUMMARY_FILE_RE);
    if (!m) continue;
    const ms = segmentStampToMs(m[1]);
    if (ms == null) continue;

    const window = m[3].toLowerCase();
    const { fields, nested, body } = parseSummaryFrontmatter(item.content || "");
    const suggestion = nested.suggestion || {};
    const deletedAt = parseIsoTimestamp(item.iso);

    rows.push(makeComputerHistoryRow({
      timestamp: formatTimestampUtc(ms),
      eventClass: CLASS_INTEGRITY,
      eventKind: "summary.deleted",
      activity: `Deleted Activity Summary (${window}, recovered)`,
      appName: fields.applications || "",
      targetRole: "SkysightSummary",
      targetLabel: fields.title || "",
      content: `RECOVERED FROM GIT — this summary was deleted from the memories repository`
        + `${deletedAt != null ? ` at ${formatTimestampUtc(deletedAt)}` : ""} (commit `
        + `${item.sha.slice(0, 12)}). ${firstNonEmpty(fields.description, truncateSummary(body))}`,
      summarySuggestion: [
        suggestion.type ? `[${suggestion.type}]` : "", suggestion.name || "",
      ].filter(Boolean).join(" "),
      summaryCitations: extractSummaryCitations(body),
      screenText: capText(String(body || "").trim(), screenTextMax),
      axLength: String(body || "").trim().length,
      fidelityTier: "",
      segmentId: `${m[1]}Z`,
      segmentStart: formatTimestampUtc(ms),
      segmentEnd: formatTimestampUtc(ms + (window === "6h" ? 6 * 60 * 60 * 1000 : SEGMENT_INTERVAL_MS)),
      sourceFile: `${gitDir}::${item.sha}:${item.filePath}`,
      recordedSourcePath: item.filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return rows;
}

/* ------------------------------------------ consolidated (phase-2) memory */

/** Lines the consolidator tagged as Skysight-derived. The tag is the provenance — do not infer. */
const SKYSIGHT_MEMORY_TAG = /\[skysight memory\]/i;
const CONSOLIDATED_MEMORY_FILES = ["memory_summary.md", "MEMORY.md", "raw_memories.md"];

/**
 * Activity intelligence that OUTLIVES the Computer History artifacts it came from.
 *
 * Skysight is not a terminus. `extensions/skysight/instructions.md` instructs the consolidator to
 * mine the summaries — naming the "Important non-obvious context about the user" section by name —
 * and fold them into the durable Codex memory at `~/.codex/memories/`. So a third copy of the
 * user's observed activity exists, one directory up from the artifacts everyone collects:
 *
 *   events.jsonl        purged after ~48h
 *   skysight/resources  until the user clears Computer History
 *   memories/*.md       INDEFINITE — a different subsystem, not cleared with Computer History
 *
 * That inverts the collection priority on a stale image. Measured on a live host: memory_summary.md
 * carried a `## User Profile` built partly from observed activity, and MEMORY.md cited a specific
 * 6h summary file by path as the evidence for a task-group memory. Thirteen lines carried the
 * explicit `[skysight memory]` provenance tag.
 *
 * Only tagged lines and blocks citing a Skysight resource are emitted. The rest of MEMORY.md is
 * ordinary Codex conversation memory — a different artifact family — and importing it wholesale
 * here would bury the activity evidence it is supposed to surface. These files are also tracked in
 * the memories git repo, so deletions are recoverable through the same path as cleared summaries.
 */
function collectSkysightDerivedMemory(target, attribution = {}) {
  const resourcesDir = findSkysightResourcesDir(target);
  // resources/ -> skysight/ -> extensions/ -> memories/
  const memoriesDir = resourcesDir
    ? path.resolve(resourcesDir, "..", "..", "..")
    : findDirBelow(target, (d) => path.basename(d) === "memories"
      && fs.existsSync(path.join(d, "MEMORY.md")));
  if (!memoriesDir || !fs.existsSync(memoriesDir)) return [];

  const rows = [];
  for (const name of CONSOLIDATED_MEMORY_FILES) {
    const filePath = path.join(memoriesDir, name);
    let st;
    let text;
    try {
      st = fs.statSync(filePath);
      text = fs.readFileSync(filePath, "utf8");
    } catch { continue; }

    const lines = text.split(/\r?\n/);
    const hits = [];
    lines.forEach((line, i) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      if (SKYSIGHT_MEMORY_TAG.test(trimmed)) hits.push({ n: i + 1, text: trimmed, why: "tagged" });
      else if (trimmed.includes("extensions/skysight/resources/")) {
        hits.push({ n: i + 1, text: trimmed, why: "cites a Skysight summary" });
      }
    });
    if (!hits.length) continue;

    for (const hit of hits) {
      rows.push(makeComputerHistoryRow({
        // No per-line time exists in these files. The file mtime is a LAST-WRITTEN bound on the
        // whole file, not the time of this line — never fabricate one from the activity it cites.
        timestamp: formatTimestampUtc(st.mtimeMs),
        eventClass: CLASS_NARRATIVE,
        eventKind: "memory.consolidated",
        activity: "Consolidated Memory (Skysight-derived)",
        targetRole: "CodexMemory",
        targetLabel: name,
        content: hit.text,
        lineNumber: hit.n,
        sourceFile: filePath,
        recordedSourcePath: filePath,
        fidelityTier: "",
        user: attribution.user || "",
        host: attribution.host || "",
      }));
      const row = rows[rows.length - 1];
      row.Description += ` | DERIVED (${hit.why}): consolidated from Computer History activity into`
        + " the durable Codex memory store. NOT purged with the 48h event stream and NOT removed by"
        + " clearing Computer History — on a stale host this may be the only surviving record."
        + " Timestamp is the file mtime, not the time of the activity described.";
    }
  }
  return rows;
}

function findComputerHistoryPluginManifest(root) {
  if (!root) return null;
  const cache = path.join(root, CODEX_DIR_NAME, "plugins", "cache", "openai-bundled", "computer-history");
  if (!fs.existsSync(cache)) return null;
  let versions;
  try { versions = fs.readdirSync(cache, { withFileTypes: true }); } catch { return null; }
  const dirs = versions.filter((e) => e.isDirectory()).map((e) => e.name).sort();
  if (!dirs.length) return null;
  const latest = dirs[dirs.length - 1];
  const filePath = path.join(cache, latest, ".codex-plugin", "plugin.json");
  if (!fs.existsSync(filePath)) return null;
  let parsed = null;
  try { parsed = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { /* keep the path */ }
  return {
    filePath,
    version: parsed && typeof parsed.version === "string" ? parsed.version : latest,
    description: parsed && typeof parsed.description === "string" ? parsed.description : "",
  };
}

/* --------------------------------------------------------- feature state */

/**
 * Feature-state artifacts: what the recorder was permitted to see, and what it was told to do.
 *
 * Without these an absence of events is unreadable — the analyst cannot tell "the user did nothing"
 * from "the recorder was not allowed to watch that app". None of them are event streams, so they
 * carry the acquisition time rather than an activity time and are marked Configuration.
 */
function collectFeatureState(target, attribution = {}) {
  const rows = [];
  const stamp = (mtime) => formatTimestampUtc(mtime);
  const identityRoot = findIdentityRoot(target);

  const addRow = (filePath, activity, content) => {
    let st;
    try { st = fs.statSync(filePath); } catch { return; }
    rows.push(makeComputerHistoryRow({
      timestamp: stamp(st.mtimeMs),
      eventClass: CLASS_CONFIG,
      eventKind: "feature.state",
      activity,
      content,
      targetRole: "ComputerHistorySettings",
      sourceFile: filePath,
      recordedSourcePath: filePath,
      fidelityTier: "",
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  };

  // Approvals for COMPUTER USE — the separate feature that lets ChatGPT drive the Mac. This is NOT
  // the Computer History recording scope, and reading it as one inverts the finding: on a live host
  // it listed a single bundle while the recorder captured 38, and its mtime predated the Computer
  // History release by three months. Recorded for what it is (which apps the agent could control),
  // never as a coverage map.
  const cuaApprovals = identityRoot
    ? path.join(
      identityRoot, "Library", "Group Containers", CUA_GROUP_DIR_NAME,
      "Library", "Application Support", "Software", "ComputerUseAppApprovals.json",
    )
    : null;
  const approvals = findFileBelow(target, "ComputerUseAppApprovals.json")
    || (cuaApprovals && fs.existsSync(cuaApprovals) ? cuaApprovals : null);
  if (approvals) {
    let parsed = null;
    try { parsed = JSON.parse(fs.readFileSync(approvals, "utf8")); } catch { /* keep the path */ }
    const bundles = Array.isArray(parsed?.approvedBundleIdentifiers)
      ? parsed.approvedBundleIdentifiers : [];
    addRow(
      approvals,
      "Computer Use Agent Approvals",
      `${bundles.length ? `${bundles.length} approved bundle(s): ${bundles.join(", ")}.`
        : "No approved bundle identifiers recorded (file present but empty or unreadable)."}`
      + " These are the apps ChatGPT was approved to CONTROL via Computer Use — a different feature"
      + " from Computer History, often predating it on disk. This is NOT the recording scope and"
      + " must not be read as a coverage map. Computer History's per-app and per-website"
      + " include/exclude settings are account-side and were not resolvable from local artifacts:"
      + " treat recording scope as UNKNOWN. Absence of events for an app may be exclusion, a pause,"
      + " an idle period, or a recorder restart — it is not evidence the app was unused.",
    );
  }

  // Whether the feature was switched on at all. Search the extract target AND the home-shaped
  // identity root — selecting the CUAService container used to miss ~/.codex/config.toml.
  const configToml = findFileBelow(target, "config.toml")
    || (identityRoot ? path.join(identityRoot, CODEX_DIR_NAME, "config.toml") : null);
  if (configToml && fs.existsSync(configToml)) {
    let text = "";
    try { text = fs.readFileSync(configToml, "utf8"); } catch { /* ignore */ }
    const pluginBody = tomlTableBody(text, /\[plugins\."computer-history@[^"]*"\]/);
    if (pluginBody != null) {
      const enabled = /enabled\s*=\s*true/.test(pluginBody);
      addRow(
        configToml,
        enabled ? "Feature Enabled" : "Feature Disabled",
        `[plugins."computer-history@…"] enabled=${enabled}. File mtime bounds when the setting was `
          + "last written — it is not the time the feature was first switched on.",
      );
    }
    const cuaBody = tomlTableBody(text, /\[mcp_servers\.computer-use\]/);
    if (cuaBody != null) {
      const cuaEnabled = /enabled\s*=\s*true/.test(cuaBody);
      addRow(
        configToml,
        cuaEnabled ? "Computer Use Agent MCP Enabled" : "Computer Use Agent MCP Disabled",
        `[mcp_servers.computer-use] enabled=${cuaEnabled}. Computer Use (agent driving the Mac) is `
          + "independent of Computer History (recording). On a measured host Computer History was "
          + "on while this MCP server was off.",
      );
    }
  }

  const pluginManifest = findComputerHistoryPluginManifest(identityRoot || target);
  if (pluginManifest) {
    addRow(
      pluginManifest.filePath,
      "Computer History Plugin Installed",
      `computer-history plugin version ${pluginManifest.version || "unknown"}`
        + `${pluginManifest.description ? ` — ${pluginManifest.description}` : ""}. `
        + "Presence of the bundled plugin cache is not by itself proof recording ran; combine with "
        + "the Feature Enabled row and the event stream.",
    );
  }

  // The prompt that governs what the summariser records — user-writable, so also a tamper surface.
  const resourcesDir = findSkysightResourcesDir(target);
  if (resourcesDir) {
    const instructions = path.join(path.dirname(resourcesDir), "instructions.md");
    if (fs.existsSync(instructions)) {
      addRow(
        instructions,
        "Summariser Instructions",
        "Skysight memory instructions — governs what the summariser records and what it promotes "
          + "into durable memory. User-writable: an edit changes every subsequent summary, so "
          + "compare the mtime against the summaries it supposedly produced.",
      );
    }
  }

  return rows;
}

/* --------------------------------------------------------- identity rows */

/**
 * Attribution artifacts: whose host this is, which pseudonym is which, and the Codex conversation
 * ledger that the event timeline joins against.
 *
 * Every identifier row states its own attribution strength in `Activity`, because the failure mode
 * here is a report claiming "the UUID links the activity to the user" without saying which UUID or
 * how. Only the account id is an account; the rest are device pseudonyms.
 *
 * Disable with `{ includeIdentity: false }`.
 */
function collectIdentityArtifacts(target, attribution = {}, options = {}) {
  const root = options.identityRoot || findIdentityRoot(target);
  if (!root) return [];

  const rows = [];
  const push = (fields) => rows.push(makeComputerHistoryRow({
    fidelityTier: "",
    user: attribution.user || "",
    host: attribution.host || "",
    ...fields,
  }));
  const mtime = (p) => {
    try { return formatTimestampUtc(fs.statSync(p).mtimeMs); } catch { return ""; }
  };

  /* --- account ids, straight out of preference FILENAMES (cheapest attribution on the box) --- */
  const prefsDir = path.join(root, "Library", "Preferences");
  const accountPlists = listAccountPlists(prefsDir);
  for (const acc of accountPlists) {
    push({
      timestamp: acc.mtimeMs != null ? formatTimestampUtc(acc.mtimeMs) : "",
      eventClass: CLASS_IDENTITY,
      eventKind: "identity.account",
      activity: `ChatGPT Account (${STRENGTH_DIRECT})`,
      targetRole: "AccountIdentifier",
      targetLabel: "chatgpt_account_id",
      identifier: acc.accountId,
      content: `ChatGPT account ${acc.accountId}, taken from the preference FILENAME — no parsing, `
        + "no tokens, survives token expiry. The file's mtime bounds when this account was last "
        + `active on the host.${accountPlists.length > 1
          ? ` NOTE: ${accountPlists.length} account-scoped preference files exist, so more than one `
            + "ChatGPT account has been used on this host." : ""}`,
      sourceFile: acc.filePath,
      recordedSourcePath: acc.filePath,
    });
  }

  const statsigAccount = readChatgptStatsigServicePlist(
    path.join(prefsDir, "com.openai.chat.StatsigService.plist"),
  );
  if (statsigAccount) {
    const parts = [
      statsigAccount.email ? `email=${statsigAccount.email}` : "",
      statsigAccount.userId ? `user=${statsigAccount.userId}` : "",
      statsigAccount.accountId ? `account=${statsigAccount.accountId}` : "",
      statsigAccount.paid ? "paid_plan=true" : "",
      statsigAccount.totalAccounts ? `totalAccounts=${statsigAccount.totalAccounts}` : "",
    ].filter(Boolean).join(", ");
    push({
      timestamp: mtime(statsigAccount.filePath),
      eventClass: CLASS_IDENTITY,
      eventKind: "identity.statsig_account",
      activity: `ChatGPT Statsig Account (${STRENGTH_DIRECT})`,
      targetRole: "StatsigService",
      targetLabel: statsigAccount.email || statsigAccount.accountId || "StatsigService",
      identifier: statsigAccount.accountId || statsigAccount.userId || "",
      content: `${parts}. Taken from com.openai.chat.StatsigService.plist — no tokens. Survives `
        + "auth.json expiry. Compare account= against the RemoteFeatureFlags filename.",
      sourceFile: statsigAccount.filePath,
      recordedSourcePath: statsigAccount.filePath,
    });
  }

  /* --- identity claims from the Codex auth token (never the token itself) --- */
  const auth = readAuthIdentity(path.join(root, ".codex", "auth.json"));
  if (auth) {
    const parts = [
      auth.email ? `email=${auth.email}` : "",
      auth.name ? `name=${auth.name}` : "",
      auth.accountId ? `account=${auth.accountId}` : "",
      auth.userId ? `user=${auth.userId}` : "",
      auth.plan ? `plan=${auth.plan}` : "",
      auth.subject ? `sub=${auth.subject}` : "",
      auth.authProvider ? `provider=${auth.authProvider}` : "",
      auth.orgs ? `orgs=${auth.orgs}` : "",
      auth.hasApiKey ? "an API key is also stored" : "",
    ].filter(Boolean).join(", ");
    push({
      timestamp: auth.authTimeMs != null ? formatTimestampUtc(auth.authTimeMs) : mtime(auth.filePath),
      eventClass: CLASS_IDENTITY,
      eventKind: "identity.auth",
      activity: `Signed-in Identity (${STRENGTH_DIRECT})`,
      targetRole: "AuthToken",
      targetLabel: auth.email || auth.accountId || "auth.json",
      identifier: auth.accountId || auth.userId || "",
      content: `${parts}. Timestamp is the token's auth_time (when the session was established). `
        + "SOURCE FILE HOLDS LIVE BEARER AND REFRESH TOKENS — treat auth.json as credential material "
        + "in collection, storage and disclosure. No token value is stored in this timeline.",
      sourceFile: auth.filePath,
      recordedSourcePath: auth.filePath,
    });
  }

  /* --- the recorder's own pseudonym, and the alias table that would bind it to an account --- */
  const analyticsPath = findFileBelow(target, "Analytics.db")
    || findFileBelow(path.join(root, "Library", "Group Containers"), "Analytics.db");
  const analytics = readAnalyticsDb(analyticsPath);
  if (analytics) {
    for (const id of analytics.distinctIds) {
      push({
        timestamp: mtime(analytics.filePath),
        eventClass: CLASS_IDENTITY,
        eventKind: "identity.distinct_id",
        activity: `Recorder Device Id (${STRENGTH_VENDOR})`,
        targetRole: "AnalyticsDistinctId",
        targetLabel: "distinct_id",
        identifier: id,
        content: `Statsig distinct_id for the Computer History recorder. This is a DEVICE pseudonym, `
          + "not an account, and it appears nowhere else on the host — it joins nothing locally. Its "
          + "value is as the key OpenAI's telemetry is indexed by, i.e. the identifier to cite in a "
          + "vendor request to resolve this capture to an account.",
        sourceFile: analytics.filePath,
        recordedSourcePath: analytics.filePath,
      });
    }
    for (const a of analytics.aliases) {
      push({
        timestamp: mtime(analytics.filePath),
        eventClass: CLASS_IDENTITY,
        eventKind: "identity.distinct_id_alias",
        activity: `Device-to-Account Alias (${STRENGTH_DIRECT})`,
        targetRole: "AnalyticsAlias",
        targetLabel: "distinct_id_alias",
        identifier: a.alias,
        content: `The anonymous device ${a.distinct_id} was aliased to ${a.alias}. This is the `
          + "analytics SDK binding an unauthenticated device to an identified user, so it is direct "
          + "local account attribution for the recorder — compare the alias against chatgpt_user_id "
          + "and chatgpt_account_id.",
        sourceFile: analytics.filePath,
        recordedSourcePath: analytics.filePath,
      });
    }
    // State the negative explicitly rather than silently producing nothing.
    if (!analytics.unreadable && !analytics.eventCount) {
      push({
        timestamp: mtime(analytics.filePath),
        eventClass: CLASS_IDENTITY,
        eventKind: "identity.analytics_empty",
        activity: "Analytics Event Store Empty (context)",
        targetRole: "AnalyticsDb",
        targetLabel: "analytics_event",
        content: "The local analytics event table holds 0 rows"
          + `${Number.isFinite(analytics.freelist) ? `, with ${analytics.freelist} of `
            + `${analytics.pageCount} pages on the freelist` : ""}. Events are uploaded then deleted `
          + "and the freed pages are zeroed, so this is expected on anything but a fast live "
          + "acquisition and the deleted events are NOT carvable. Absence here is not evidence that "
          + "the feature was unused.",
        sourceFile: analytics.filePath,
        recordedSourcePath: analytics.filePath,
      });
    }
  }

  /* --- per-app Statsig device ids, and the evaluation cache that outlives the 48h purge --- */
  for (const app of ["com.openai.sky.CUAService", "com.openai.chat", "com.openai.codex"]) {
    const plistPath = path.join(prefsDir, `${app}.plist`);
    if (!fs.existsSync(plistPath)) continue;
    const store = readStatsigStore(plistPath);
    if (!store) continue;

    if (store.stableId) {
      push({
        timestamp: mtime(plistPath),
        eventClass: CLASS_IDENTITY,
        eventKind: "identity.statsig_stable_id",
        activity: `App Device Id (${STRENGTH_DEVICE})`,
        targetRole: "StatsigStableId",
        targetLabel: app,
        identifier: store.stableId,
        content: `Statsig stable id for ${app}. Each OpenAI app generates its OWN device pseudonym, `
          + "so several of these on one host are the same machine — not several machines, and not "
          + "an account.",
        sourceFile: plistPath,
        recordedSourcePath: plistPath,
      });
    }

    for (const ctx of store.contexts) {
      if (ctx.evaluatedMs == null) continue;
      push({
        timestamp: formatTimestampUtc(ctx.evaluatedMs),
        eventClass: CLASS_IDENTITY,
        eventKind: "identity.statsig_evaluation",
        activity: `App Running (${STRENGTH_TIMELINE})`,
        targetRole: "StatsigEvaluation",
        targetLabel: app,
        identifier: String(ctx.userHash ?? ctx.key ?? ""),
        content: `${app} evaluated feature flags at this time, so the process was alive. Raw events `
          + "are purged after ~48h but this cache persists, which extends the presence timeline well "
          + "beyond the event stream. PROVES THE PROCESS RAN — not that recording was enabled, and "
          + "not that the user was active.",
        sourceFile: plistPath,
        recordedSourcePath: plistPath,
      });
    }
  }

  /* --- Codex install ids and the UUIDv7 conversation ledger --- */
  const codex = readCodexIdentity(path.join(root, ".codex"));
  if (codex) {
    if (codex.installationId) {
      push({
        timestamp: mtime(codex.installationIdPath),
        eventClass: CLASS_IDENTITY,
        eventKind: "identity.installation_id",
        activity: `Codex Install Id (${STRENGTH_DEVICE})`,
        targetRole: "CodexInstallationId",
        targetLabel: "installation_id",
        identifier: codex.installationId,
        content: "Codex (Electron) install identifier — lowercase UUID, a different namespace from "
          + "the native service's uppercase distinct_id. Same machine, different pseudonym.",
        sourceFile: codex.installationIdPath,
        recordedSourcePath: codex.installationIdPath,
      });
    }
    if (codex.environmentId) {
      push({
        timestamp: mtime(codex.statePath),
        eventClass: CLASS_IDENTITY,
        eventKind: "identity.environment_id",
        activity: `Codex Environment Id (${STRENGTH_VENDOR})`,
        targetRole: "CodexEnvironmentId",
        targetLabel: "environment-id",
        identifier: codex.environmentId,
        content: "Server-issued environment identifier. Secondary key for a vendor request.",
        sourceFile: codex.statePath,
        recordedSourcePath: codex.statePath,
      });
    }

    for (const t of codex.threads) {
      push({
        timestamp: formatTimestampUtc(t.createdMs),
        eventClass: t.deleted ? CLASS_INTEGRITY : CLASS_SESSION,
        eventKind: t.deleted ? "codex.thread.deleted" : "codex.thread.created",
        activity: t.deleted ? "Codex Thread Deleted (recoverable context)" : "Codex Thread Created",
        targetRole: "CodexThread",
        targetLabel: t.id,
        identifier: t.id,
        content: t.deleted
          ? `Codex conversation ${t.id} was created at this time and is marked DELETED in global `
            + "state. The conversation is gone, but Computer History rows in this same window may "
            + "still hold the model chosen and the prompt typed into it — deleting the conversation "
            + "does not delete the record of it. Timestamp decoded from the UUIDv7."
          : `Codex conversation ${t.id} created. Timestamp decoded from the UUIDv7 itself, so it is `
            + "independent of any file mtime. Use it to join conversations to the event timeline.",
        sourceFile: codex.statePath,
        recordedSourcePath: codex.statePath,
      });
    }
  }

  return rows;
}

/** Bounded downward search for a single file by name, staying inside `rootDir`. */
function findFileBelow(rootDir, fileName, maxDepth = MAX_DISCOVERY_DEPTH) {
  if (!rootDir || !fs.existsSync(rootDir)) return null;
  let base = rootDir;
  try {
    if (fs.statSync(base).isFile()) base = path.dirname(base);
  } catch { return null; }

  const direct = path.join(base, fileName);
  if (fs.existsSync(direct)) return direct;

  const queue = [{ d: base, depth: 0 }];
  while (queue.length) {
    const { d, depth } = queue.shift();
    if (depth >= maxDepth) continue;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isFile() && e.name === fileName) return path.join(d, e.name);
      if (e.isDirectory() && !e.isSymbolicLink()) queue.push({ d: path.join(d, e.name), depth: depth + 1 });
    }
  }
  return null;
}

/* ------------------------------------------------------------- extraction */

async function extractSegmentFile(segmentDir, attribution = {}, options = {}, parseStats = null) {
  const eventsPath = path.join(segmentDir, EVENTS_FILE);
  const segmentId = path.basename(segmentDir);
  const meta = readSegmentMetadata(segmentDir);
  const ctx = {
    segmentId,
    segmentStart: meta.startedAt || formatTimestampUtc(segmentStampToMs(segmentId)),
    segmentEnd: meta.endedAt,
    segmentSuppressed: meta.suppressedEventCount,
    segmentEventCount: meta.eventCount,
    recordedSourcePath: meta.recordedEventsPath,
  };

  const rows = [];

  // Count every JSONL record the file actually holds — including ones that never became a row —
  // so the reconciliation below measures the FILE against its metadata, not our parse yield.
  const segStats = { errors: 0 };
  let recordsRead = 0;

  await readJsonlBounded(eventsPath, (obj, lineNumber) => {
    recordsRead += 1;
    const row = parseSkysightEvent(obj, eventsPath, ctx, attribution, options);
    if (!row) return;
    row.LineNumber = String(lineNumber);
    rows.push(row);
  }, { parseStats: segStats });
  if (parseStats) parseStats.errors += segStats.errors;

  // `eventCount` is the number of events the recorder WROTE, so it is compared against well-formed
  // records — not raw line count. It matched exactly on every closed segment measured live, which
  // makes it a usable integrity anchor: the docs advertise "clear the last 10 minutes / hour / day",
  // and a clear removes records while leaving this count behind.
  //
  // Malformed lines are counted separately rather than folded in. Both a deletion and a corruption
  // lower the valid-record count, but they are different findings and an analyst needs to see which
  // one this is — folding them together reports corruption as "records were appended".
  const recordsPresent = recordsRead;
  const countDelta = meta.eventCount != null && !meta.open ? recordsPresent - meta.eventCount : null;

  if (options.includeSegmentBoundaries !== false) {
    const startMs = parseIsoTimestamp(meta.startedAt) ?? segmentStampToMs(segmentId);
    if (startMs != null) {
      const notes = [
        meta.eventCount != null ? `eventCount=${meta.eventCount}` : null,
        `recordsPresent=${recordsPresent}`,
        segStats.errors ? `malformedLines=${segStats.errors}` : null,
        meta.suppressedEventCount != null ? `suppressedEventCount=${meta.suppressedEventCount}` : null,
        meta.open ? "segment OPEN at acquisition (hash provisional; count not reconciled)" : null,
        countDelta === 0 ? "reconciled: record count matches metadata" : null,
      ].filter(Boolean).join(", ");
      rows.push(makeComputerHistoryRow({
        timestamp: formatTimestampUtc(startMs),
        eventClass: CLASS_SESSION,
        eventKind: "segment.boundary",
        activity: "Segment Boundary",
        content: notes,
        segmentId,
        segmentStart: ctx.segmentStart,
        segmentEnd: ctx.segmentEnd,
        segmentSuppressed: meta.suppressedEventCount,
        segmentEventCount: meta.eventCount,
        segmentCountDelta: countDelta,
        sourceFile: path.join(segmentDir, METADATA_FILE),
        recordedSourcePath: meta.recordedEventsPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }

    // A mismatch is the cheapest deletion signal this artifact offers — surface it as its own row
    // rather than burying it in a boundary note.
    if (countDelta != null && countDelta !== 0) {
      const startMs = parseIsoTimestamp(meta.startedAt) ?? segmentStampToMs(segmentId);
      const missing = -countDelta;
      rows.push(makeComputerHistoryRow({
        timestamp: formatTimestampUtc(startMs ?? Date.now()),
        eventClass: CLASS_INTEGRITY,
        eventKind: "segment.integrity",
        activity: missing > 0 ? "Record Count Short (derived)" : "Record Count Over (derived)",
        content: missing > 0
          ? `Metadata declares ${meta.eventCount} event(s) for this closed bucket but the file holds `
            + `${recordsPresent} well-formed record(s). ${missing} record(s) are missing from `
            + "events.jsonl after the count was written — consistent with a history-clear or a "
            + `targeted deletion.${segStats.errors ? ` NOTE: ${segStats.errors} malformed line(s) `
              + "were also skipped, so corruption or truncation may account for some of the "
              + "shortfall rather than deletion." : ""} Derived by reconciliation, not an observed event.`
          : `The file holds ${recordsPresent} well-formed record(s) against a declared `
            + `${meta.eventCount}. Records were appended after the count was written, or the `
            + "metadata is stale. Derived by reconciliation, not an observed event.",
        segmentId,
        segmentStart: ctx.segmentStart,
        segmentEnd: ctx.segmentEnd,
        segmentEventCount: meta.eventCount,
        segmentCountDelta: countDelta,
        sourceFile: path.join(segmentDir, METADATA_FILE),
        recordedSourcePath: meta.recordedEventsPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }
  }

  rows._countDelta = countDelta;

  // `_deferCoalesce` lets the directory extractor coalesce once, globally, after the merged rows are
  // sorted — a composition interrupted by a 10-minute bucket rollover spans two files and would
  // otherwise be split at the boundary.
  if (options.coalesceTypedInput === false || options._deferCoalesce) return rows;
  const out = coalesceTypedInput(rows);
  out._countDelta = countDelta;
  return out;
}

function sortRows(rows) {
  rows.sort((a, b) => {
    if (a.Timestamp !== b.Timestamp) return a.Timestamp < b.Timestamp ? -1 : 1;
    // Same-second events: the session-global counter is the true order.
    const ea = Number(a.EventId); const eb = Number(b.EventId);
    if (Number.isFinite(ea) && Number.isFinite(eb) && ea !== eb) return ea - eb;
    return 0;
  });
  return rows;
}

function numberRows(rows) {
  for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
  return rows;
}

function sortAndNumberRows(rows) {
  return numberRows(sortRows(rows));
}

function dedupeRows(rows) {
  const seen = new Set();
  const out = [];
  for (const r of rows) {
    // EventId is session-global and unique; segment id disambiguates re-collected/overlapping dumps.
    const key = r.EventId
      ? `${r.SegmentId}\x1e${r.EventId}`
      : `${r.SourceFile}\x1e${r.Timestamp}\x1e${r.EventKind}\x1e${r.Activity}\x1e${r.LineNumber}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

/**
 * Extract every Computer History row reachable from a resolved evidence root.
 * `target` may be a group container, a segments dir, a .codex dir, or a triage root holding either.
 */
async function extractComputerHistoryDir(target, attribution = {}, options = {}) {
  const segmentsDir = findSegmentsDir(target);
  const resourcesDir = findSkysightResourcesDir(target);
  if (!segmentsDir && !resourcesDir) {
    throw new Error("No ChatGPT Computer History (Skysight) artifacts found under this path.");
  }

  const parseStats = { errors: 0 };
  const segmentDirs = segmentsDir ? listSegmentDirs(segmentsDir) : [];
  const summaryFiles = resourcesDir ? listSummaryFiles(resourcesDir) : [];
  const fileCount = segmentDirs.length + summaryFiles.length;
  let fileIndex = 0;

  const rows = [];
  const { onFileProgress, onExtractedRows } = options;
  const emit = (batch) => {
    if (!batch?.length) return;
    if (onExtractedRows) onExtractedRows(batch);
    else rows.push(...batch);
  };

  // Per-bucket event-id ranges, collected as each segment lands so gap detection can tell an idle
  // host from a deleted bucket. Works in streaming mode too, where no merged row set ever exists.
  const idRanges = new Map();
  const recordIdRange = (batch, dir) => {
    const segmentId = path.basename(dir);
    for (const r of batch || []) {
      // A recorder restart zeroes the id counter, so a bucket containing session.started shares no
      // id namespace with the bucket before it. Flagged here because it is the authoritative
      // boundary marker — the id reset alone can be ambiguous when the previous run was very short.
      if (r.EventKind === "session.started") {
        const cur = idRanges.get(segmentId);
        if (cur) cur.sessionStart = true;
        else idRanges.set(segmentId, { min: Infinity, max: -Infinity, sessionStart: true });
      }
      // Synthetic rows (segment.boundary) carry EventId "" — and Number("") is 0, which would drag
      // every bucket's minimum to zero and make the continuity check meaningless.
      if (!r.EventId) continue;
      const n = Number(r.EventId);
      if (!Number.isFinite(n)) continue;
      const cur = idRanges.get(segmentId);
      if (!cur) idRanges.set(segmentId, { min: n, max: n, sessionStart: false });
      else { if (n < cur.min) cur.min = n; if (n > cur.max) cur.max = n; }
    }
  };
  // bundle -> largest observed fullTree AX capture, for per-app fidelity tiering at finalization.
  const axProfile = new Map();
  let countDeltaTotal = 0;
  let integrityFlagged = 0;
  const recordCountDelta = (batch) => {
    const d = batch?._countDelta;
    if (d == null || d === 0) return;
    integrityFlagged += 1;
    countDeltaTotal += d;
  };

  // Streaming sinks see rows before the merged set exists, so they coalesce per file and a
  // composition split across a bucket rollover stays split. Buffered callers get the global pass.
  const segmentOptions = onExtractedRows
    ? { ...options, axProfile }
    : { ...options, axProfile, _deferCoalesce: true };

  await processFilesConcurrently(segmentDirs, {
    process: (dir) => extractSegmentFile(dir, attribution, segmentOptions, parseStats),
    onProgress: (dir) => {
      fileIndex += 1;
      tickFileProgress(onFileProgress, fileIndex, fileCount, path.join(dir, EVENTS_FILE));
    },
    onRows: (batch, dir) => { recordIdRange(batch, dir); recordCountDelta(batch); emit(batch); },
    onError: (e, dir) => dbg("AIHIST", "computer-history segment failed", { path: dir, err: e.message }),
    checkAbort: options.checkAbort,
  });

  for (const filePath of summaryFiles) {
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, fileCount, filePath);
    try {
      const summaryRows = parseSummaryFileRows(filePath, attribution, options);
      if (summaryRows.length) emit(summaryRows);
    } catch (e) {
      dbg("AIHIST", "computer-history summary failed", { path: filePath, err: e.message });
    }
  }

  const gapRows = options.detectGaps === false || !segmentsDir
    ? []
    : detectSegmentGaps(
      segmentDirs.map((d) => path.basename(d)), segmentsDir, attribution, idRanges,
    );
  if (gapRows.length) emit(gapRows);

  // Summaries the user cleared, recovered from the memories git object store.
  let recoveredRows = [];
  if (options.recoverDeleted !== false && resourcesDir) {
    try {
      recoveredRows = await recoverDeletedSummaries(resourcesDir, attribution, options);
    } catch (e) {
      dbg("AIHIST", "computer-history recovery failed", { path: resourcesDir, err: e.message });
    }
    if (recoveredRows.length) emit(recoveredRows);
  }

  const stateRows = options.includeFeatureState === false
    ? []
    : collectFeatureState(target, attribution);
  if (stateRows.length) emit(stateRows);

  // Activity intelligence consolidated into the durable Codex memory — the copy that survives both
  // the 48h purge and a "clear Computer History".
  let memoryRows = [];
  if (options.includeConsolidatedMemory !== false) {
    try {
      memoryRows = collectSkysightDerivedMemory(target, attribution);
    } catch (e) {
      dbg("AIHIST", "computer-history consolidated memory failed", { path: target, err: e.message });
    }
    if (memoryRows.length) emit(memoryRows);
  }

  // Attribution: who this host belongs to, and the Codex conversation ledger the timeline joins to.
  let identityRows = [];
  if (options.includeIdentity !== false) {
    try {
      identityRows = collectIdentityArtifacts(target, attribution, options);
    } catch (e) {
      dbg("AIHIST", "computer-history identity failed", { path: target, err: e.message });
    }
    if (identityRows.length) emit(identityRows);
  }

  const stats = {
    segmentsDir: segmentsDir || "",
    resourcesDir: resourcesDir || "",
    segmentCount: segmentDirs.length,
    summaryCount: summaryFiles.length,
    gapCount: gapRows.length,
    recoveredCount: recoveredRows.length,
    featureStateCount: stateRows.length,
    consolidatedMemoryCount: memoryRows.length,
    identityCount: identityRows.length,
    accountCount: identityRows.filter((r) => r.EventKind === "identity.account").length,
    deletedThreadCount: identityRows.filter((r) => r.EventKind === "codex.thread.deleted").length,
    integritySegments: integrityFlagged,
    integrityDelta: countDeltaTotal,
    suppressedTotal: segmentDirs.reduce((n, d) => {
      const s = readSegmentMetadata(d).suppressedEventCount;
      return n + (Number.isFinite(s) ? s : 0);
    }, 0),
  };

  stats.axProfile = Object.fromEntries(axProfile);

  if (onExtractedRows) {
    const out = [];
    out._computerHistoryStats = stats;
    if (parseStats.errors) out._parseErrors = parseStats.errors;
    return out;
  }

  let merged = sortRows(dedupeRows(rows));
  if (options.coalesceTypedInput !== false) merged = coalesceTypedInput(merged);
  // Tier every app once, now that the whole capture has been seen.
  stampFidelityTiers(merged, axProfile);
  const finalized = numberRows(merged);
  finalized._computerHistoryStats = stats;
  if (parseStats.errors) finalized._parseErrors = parseStats.errors;
  return finalized;
}

/**
 * Entry point matching the ai-history extractor contract.
 * Accepts a directory (container / segments / .codex / triage root) or a single
 * `events.jsonl` / `<ts>-<id>-(10min|6h)-*.md` file.
 */
async function extractComputerHistoryPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  let stat;
  try { stat = fs.statSync(target); } catch (e) {
    throw new Error(`Cannot read path: ${e.message}`);
  }

  if (stat.isDirectory()) {
    return extractComputerHistoryDir(target, attribution, options);
  }

  if (isSkysightEventsFile(target)) {
    const parseStats = { errors: 0 };
    const axProfile = new Map();
    const rows = await extractSegmentFile(
      path.dirname(target), attribution, { ...options, axProfile }, parseStats,
    );
    const finalized = sortAndNumberRows(stampFidelityTiers(dedupeRows(rows), axProfile));
    if (parseStats.errors) finalized._parseErrors = parseStats.errors;
    return finalized;
  }

  if (isSkysightSummaryFile(target)) {
    const summaryRows = parseSummaryFileRows(target, attribution, options);
    if (!summaryRows.length) throw new Error("Unreadable Skysight summary file.");
    summaryRows.forEach((r, i) => { r.RecordId = String(i + 1); });
    return summaryRows;
  }

  throw new Error(
    "Expected a Skysight events.jsonl, a *-10min-*.md / *-6h-*.md summary, or a directory containing them.",
  );
}

module.exports = {
  CUA_GROUP_DIR_NAME,
  SEGMENTS_REL,
  SKYSIGHT_RESOURCES_REL,
  SEGMENT_DIR_RE,
  SUMMARY_FILE_RE,
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
  defaultComputerHistoryRoots,
  resolveEventClass,
  resolveAppClass,
  resolveFidelityTier,
  stampFidelityTiers,
  extractSummaryCitations,
  extractSummarySection,
  recoverDeletedSummaries,
  collectFeatureState,
  collectSkysightDerivedMemory,
  collectIdentityArtifacts,
  describeActivity,
  makeComputerHistoryRow,
  parseSkysightEvent,
  coalesceTypedInput,
  isScrollbackSnapshot,
  isTypingContinuation,
  readSegmentMetadata,
  listSegmentDirs,
  detectSegmentGaps,
  parseSummaryFrontmatter,
  listSummaryFiles,
  parseSummaryFile,
  parseSummaryFileRows,
  SUMMARY_SECTIONS,
  extractSegmentFile,
  extractComputerHistoryDir,
  extractComputerHistoryPath,
  dedupeRows,
  TOOL_COMPUTER_HISTORY,
  TERMINAL_VALUE_KIND,
  isTerminalValueChanged,
  extractTerminalBuffer,
  describeTerminalActivity,
};
