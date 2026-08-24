/**
 * ai-history/computer-history-schema.js — column schema for ChatGPT "Computer History" (Skysight).
 *
 * This is deliberately NOT the AI_HISTORY_COLUMNS schema. AI history rows are prompt/response
 * conversation turns (Role/Summary/FullText/Model/Tokens). Computer History rows are OS-level
 * user-activity telemetry: focus changes, keystrokes, clicks, drags, selections and window/URL
 * context. Forcing them into the conversation schema would leave ~60% of columns empty and drop
 * the fields that carry the actual evidence (BundleId, TargetRole, drag origin→destination,
 * capture fidelity).
 *
 * Column groups:
 *   When         Timestamp, EventId, SegmentId, SegmentStart, SegmentEnd, SegmentSuppressed,
 *                SegmentEventCount, SegmentCountDelta
 *   What         EventClass, AppClass, EventKind, Activity
 *   Where        AppName, BundleId, WindowTitle, Url
 *   Target       TargetRole, TargetSubrole, TargetLabel, TargetDescription, TargetId
 *   Payload      Content, ContentLength, TypedDelta, KeyChord, MouseButton, ClickCount,
 *                SelectionOffset, SelectionLength, SelectedItems, SelectedItemRoles,
 *                SelectedItemCount
 *   Movement     DestAppName, DestBundleId, DestWindowTitle, DestUrl, DestTargetRole,
 *                DestTargetSubrole, DestTargetLabel, DestContent
 *   Capture      FidelityTier, AxMode, AxLength, ScreenText
 *   Narrative    SummarySuggestion, SummaryCitations
 *   Attribution  Identifier
 *   Provenance   SourceFile, RecordedSourcePath, LineNumber, User, Host, Description, RecordId
 *
 * EventClass vs AppClass: EventClass describes WHAT THE USER DID (derived from `.kind` — typing is
 * Input wherever it happens). AppClass describes WHERE (derived from the bundle id — Slack is
 * Communication whatever you do in it). They are orthogonal and were previously conflated, which
 * reclassified ~86% of Input events away from Input and broke "find everything the user typed".
 */

const COMPUTER_HISTORY_COLUMNS = [
  "Timestamp",
  "EventClass",
  "AppClass",
  "EventKind",
  "Activity",
  "AppName",
  "BundleId",
  "WindowTitle",
  "Url",
  "TargetRole",
  "TargetSubrole",
  "TargetLabel",
  "TargetDescription",
  "TargetId",
  "Content",
  "ContentLength",
  "TypedDelta",
  "KeyChord",
  "MouseButton",
  "ClickCount",
  "SelectionOffset",
  "SelectionLength",
  "SelectedItems",
  "SelectedItemRoles",
  "SelectedItemCount",
  "DestAppName",
  "DestBundleId",
  "DestWindowTitle",
  "DestUrl",
  "DestTargetRole",
  "DestTargetSubrole",
  "DestTargetLabel",
  "DestContent",
  "FidelityTier",
  "AxMode",
  "AxLength",
  "ScreenText",
  "EventId",
  "SegmentId",
  "SegmentStart",
  "SegmentEnd",
  "SegmentSuppressed",
  "SegmentEventCount",
  "SegmentCountDelta",
  "SummarySuggestion",
  "SummaryCitations",
  "Identifier",
  "SourceFile",
  "RecordedSourcePath",
  "LineNumber",
  "User",
  "Host",
  "Description",
  "RecordId",
];

const TOOL_COMPUTER_HISTORY = "ChatGPT Computer History";
/** Extractor key in the ai-history registry and the renderer menu action. */
const COMPUTER_HISTORY_TOOL_ID = "computer-history";

/** Evidence classes — see docs/dfir-tips (Computer History taxonomy). */
const CLASS_SESSION = "Session";
const CLASS_EXECUTION = "Execution";
const CLASS_WEB = "Web";
const CLASS_COMMUNICATION = "Communication";
const CLASS_INPUT = "Input";
const CLASS_UI = "UIInteraction";
const CLASS_DATA_MOVEMENT = "DataMovement";
const CLASS_TERMINAL = "Terminal";
const CLASS_FILESYSTEM = "FileSystem";
const CLASS_NOTIFICATION = "Notification";
const CLASS_NARRATIVE = "Narrative";
/** Feature state — what the recorder was configured to capture, and what it was blind to. */
const CLASS_CONFIG = "Configuration";
/** Derived integrity assertions (count reconciliation, recovered deletions). */
const CLASS_INTEGRITY = "Integrity";
/** Attribution — who this host belongs to, and which pseudonym is which. */
const CLASS_IDENTITY = "Identity";

const COMPUTER_HISTORY_CLASSES = [
  CLASS_SESSION,
  CLASS_EXECUTION,
  CLASS_WEB,
  CLASS_COMMUNICATION,
  CLASS_INPUT,
  CLASS_UI,
  CLASS_DATA_MOVEMENT,
  CLASS_TERMINAL,
  CLASS_FILESYSTEM,
  CLASS_NOTIFICATION,
  CLASS_NARRATIVE,
  CLASS_CONFIG,
  CLASS_INTEGRITY,
  CLASS_IDENTITY,
];

/** Base class per raw `.kind`. App-family overrides refine this (see APP_CLASS_OVERRIDES). */
const KIND_CLASS = {
  "session.started": CLASS_SESSION,
  "session.ended": CLASS_SESSION,
  "window.changed": CLASS_EXECUTION,
  "mouse.click": CLASS_UI,
  "mouse.context_menu": CLASS_UI,
  "mouse.drag": CLASS_DATA_MOVEMENT,
  "selection.changed": CLASS_DATA_MOVEMENT,
  "keyboard.text_input": CLASS_INPUT,
  "keyboard.submit": CLASS_INPUT,
  "keyboard.shortcut": CLASS_INPUT,
  // Visible terminal scrollback while Secure Input blocks keystroke capture.
  "terminal.value_changed": CLASS_TERMINAL,
};

/**
 * App-family classification — the value of the `AppClass` column, and the class of a `window.changed`
 * focus row.
 *
 * This is NOT applied to other event kinds. A click inside Slack stays `EventClass: UIInteraction`
 * and typing in iTerm2 stays `EventClass: Input`; the Slack/Terminal fact travels in `AppClass`
 * instead. Applying it to every kind (the pre-1.0.9 behaviour) reclassified 801 of ~930 Input events
 * away from Input, so filtering `EventClass = Input` to find typed content missed every keystroke in
 * the messaging and terminal apps where it matters most.
 */
const APP_CLASS_OVERRIDES = {
  "com.tinyspeck.slackmacgap": CLASS_COMMUNICATION,
  "ru.keepcoder.Telegram": CLASS_COMMUNICATION,
  "net.whatsapp.WhatsApp": CLASS_COMMUNICATION,
  "com.apple.MobileSMS": CLASS_COMMUNICATION,
  "com.apple.iChat": CLASS_COMMUNICATION,
  "com.apple.mail": CLASS_COMMUNICATION,
  "com.microsoft.Outlook": CLASS_COMMUNICATION,
  "com.hnc.Discord": CLASS_COMMUNICATION,
  "us.zoom.xos": CLASS_COMMUNICATION,
  "com.microsoft.teams2": CLASS_COMMUNICATION,
  "com.googlecode.iterm2": CLASS_TERMINAL,
  "com.apple.Terminal": CLASS_TERMINAL,
  "dev.warp.Warp-Stable": CLASS_TERMINAL,
  "net.kovidgoyal.kitty": CLASS_TERMINAL,
  "com.github.wez.wezterm": CLASS_TERMINAL,
  "co.zeit.hyper": CLASS_TERMINAL,
  "com.apple.finder": CLASS_FILESYSTEM,
  "com.apple.UserNotificationCenter": CLASS_NOTIFICATION,
  "com.apple.notificationcenterui": CLASS_NOTIFICATION,
  "com.apple.loginwindow": CLASS_SESSION,
};

/**
 * Capture-fidelity tier per app family. Everything Skysight records flows through the macOS
 * Accessibility API, so how much content lands on disk depends on how the app renders its UI:
 *
 *   Tier 1  Deep      Chromium/Electron/WebKit views and terminal emulators expose full text.
 *                     Terminals expose the whole scrollback buffer as a single AXTextArea.
 *   Tier 2  Structural Navigation structure, labels and counts; message/document bodies collapsed.
 *   Tier 3  Metadata  Hardened or custom-drawn native UI. Window title + bundle id only.
 *
 * This table is a PRIOR, not a verdict. resolveFidelityTier takes the more capable of this value
 * and what the app actually produced in the capture at hand, because each source fails in a
 * different direction: the table goes stale when an app changes toolkit, and the measurement
 * understates any app that was only briefly on screen. Neither may be trusted alone.
 *
 * The tier tracks the UI TOOLKIT, not the product category. Measured on one live capture: Telegram
 * exposed a largest-ever full tree of 144 characters (window/menu labels — genuinely Tier 3) while
 * Slack, an Electron app, exposed 53,590 including channel message bodies, thread markers and
 * per-message timestamps. Two messaging apps, three orders of magnitude apart. Slack was pinned to
 * Tier 3 here on category reasoning alone and produced exactly the wrong report sentence.
 *
 * FORENSIC CAVEAT (must survive into any report): in a genuine Tier 3 app, OUTBOUND typed text is
 * still captured (keyboard events are hardware-level and app-independent) while INBOUND message
 * content is not (it only ever appears via the AX tree). Such a capture is one side of a
 * conversation and must never be presented as a conversation record. Confirm the tier against
 * AxLength for that bundle in the capture in front of you before writing that sentence — or its
 * opposite.
 */
const FIDELITY_TIER_BY_BUNDLE = {
  // Tier 1 — deep content
  "com.microsoft.edgemac": 1,
  "com.google.Chrome": 1,
  "com.google.Chrome.canary": 1,
  "com.apple.Safari": 1,
  "com.brave.Browser": 1,
  "org.mozilla.firefox": 1,
  "company.thebrowser.Browser": 1,
  "com.talon-sec.Work": 1,
  "com.openai.chat": 1,
  "com.openai.codex": 1,
  "com.anthropic.claudefordesktop": 1,
  "com.googlecode.iterm2": 1,
  "com.apple.Terminal": 1,
  "dev.warp.Warp-Stable": 1,
  "com.microsoft.VSCode": 1,
  // Cursor. `com.anysphere.sand` was listed here as Cursor and is not — on a live host it resolves
  // to an unrelated app ("Grok Bot") whose largest full tree was 12,916 chars. Cursor's real bundle
  // is the todesktop id below, which was absent from the table entirely.
  "com.todesktop.230313mzl4w4u92": 1,
  // Electron — exposes the full rendered tree, message bodies included. Do not demote on the
  // grounds that it is a chat app; see the toolkit note above.
  "com.tinyspeck.slackmacgap": 1,
  "com.hnc.Discord": 1,
  // Tier 2 — structural
  "com.spotify.xirp": 2,
  "net.whatsapp.WhatsApp": 2,
  "com.apple.finder": 2,
  "com.apple.mail": 2,
  // Tier 3 — metadata only
  "ru.keepcoder.Telegram": 3,
  "com.apple.UserNotificationCenter": 3,
  "com.apple.notificationcenterui": 3,
  "com.apple.dock": 3,
  "com.apple.dock.helper": 3,
  "com.apple.loginwindow": 3,
};

/**
 * Heuristic tier bounds for bundle ids absent from the table.
 *
 * These are measured against the LARGEST `fullTree` AX capture observed for that bundle across the
 * whole extraction — never a single event's length. Fidelity is a property of the application, not
 * of one event: 43% of events carry no `ax` object at all, and `diffFromPrevious` events are short
 * by construction, so per-event tiering made the same app report Tier 1, 2 and 3 on adjacent rows
 * and left an analyst unable to scope what evidence could exist. See resolveFidelityTier.
 */
const TIER1_MIN_AX_CHARS = 20000;
const TIER2_MIN_AX_CHARS = 2000;

/**
 * AX subroles that change how a payload must be read.
 *
 * `AXSecureTextField` is a password field: macOS never exposes its value through the accessibility
 * API, but the keyboard events are captured at the hardware level and are app-independent — so the
 * typed characters DO land in the stream while the field itself reads as empty. Any row whose target
 * carries this subrole is a credential-entry event and must be treated as such.
 */
const SECURE_TEXT_SUBROLE = "AXSecureTextField";
const SEARCH_FIELD_SUBROLE = "AXSearchField";

/**
 * `ax.mode` values. `fullTree` is a snapshot of the visible accessibility tree; `diffFromPrevious`
 * carries ONLY what changed since the previous snapshot. They are not interchangeable — a diff read
 * as a screen snapshot understates what was on screen, so ScreenText must always be qualified by
 * the mode that produced it.
 */
const AX_MODE_FULL = "fullTree";
const AX_MODE_DIFF = "diffFromPrevious";

/** Bound a single retained payload. AX trees observed up to ~106K chars for one event. */
const MAX_CONTENT_CHARS = 1024 * 1024;
const DEFAULT_SCREEN_TEXT_MAX_CHARS = 64 * 1024;
const ACTIVITY_PREVIEW_LEN = 150;

/** Segment buckets are fixed 10-minute UTC windows; used for gap detection. */
const SEGMENT_INTERVAL_MS = 10 * 60 * 1000;

module.exports = {
  COMPUTER_HISTORY_COLUMNS,
  COMPUTER_HISTORY_CLASSES,
  TOOL_COMPUTER_HISTORY,
  COMPUTER_HISTORY_TOOL_ID,
  CLASS_SESSION,
  CLASS_EXECUTION,
  CLASS_WEB,
  CLASS_COMMUNICATION,
  CLASS_INPUT,
  CLASS_UI,
  CLASS_DATA_MOVEMENT,
  CLASS_TERMINAL,
  CLASS_FILESYSTEM,
  CLASS_NOTIFICATION,
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
  SEARCH_FIELD_SUBROLE,
  AX_MODE_FULL,
  AX_MODE_DIFF,
  MAX_CONTENT_CHARS,
  DEFAULT_SCREEN_TEXT_MAX_CHARS,
  ACTIVITY_PREVIEW_LEN,
  SEGMENT_INTERVAL_MS,
};
