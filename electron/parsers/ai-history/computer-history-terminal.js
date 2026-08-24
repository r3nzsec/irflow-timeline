/**
 * computer-history-terminal.js — Skysight `terminal.value_changed` events.
 *
 * This kind is not in the original 1.0.10/1.0.11 event catalog. On a live 16,173-event
 * capture it appeared 9 times, always while macOS Secure Input Mode was engaged, and
 * carried the visible iTerm2 scrollback in `keyboard.target.value`.
 *
 * Why it exists: when a password field (or SSH/sudo prompt) engages Secure Input, the
 * recorder's event tap is blocked, so `keyboard.text_input` never writes the keystrokes.
 * The accessibility tree of the terminal still updates. Skysight emits this kind for
 * that buffer change. The typed password is NOT in the payload. The command that
 * triggered the prompt IS — `ssh user@host`, `rsync …`, `scp .env …`.
 *
 * Without a dedicated parse, `parseSkysightEvent` fell through to `content = ""` and
 * the analyst saw an empty Terminal row at the moment of the authentication.
 *
 * The buffer is the VISIBLE AX range. Some records are prefixed
 * `[truncated to visible range]` — that is not the full scrollback.
 */

const TERMINAL_VALUE_KIND = "terminal.value_changed";
const VISIBLE_RANGE_PREFIX = "[truncated to visible range]";

function isTerminalValueChanged(kind) {
  return String(kind || "").trim() === TERMINAL_VALUE_KIND;
}

function extractTerminalBuffer(ev) {
  const target = ev && ev.keyboard && ev.keyboard.target && typeof ev.keyboard.target === "object"
    ? ev.keyboard.target
    : {};
  const raw = typeof target.value === "string" ? target.value : "";
  const truncatedVisible = raw.startsWith(VISIBLE_RANGE_PREFIX);
  return {
    content: raw,
    truncatedVisible,
    targetRole: typeof target.role === "string" ? target.role : "",
    targetDescription: typeof target.description === "string" ? target.description : "",
    targetValueLength: raw.length,
  };
}

function windowLooksLikeSsh(ev) {
  const title = String(ev?.window?.title || "").trim();
  // `\bssh\b` matches the "ssh" in "ssh-keygen". Only the session titles observed live.
  return /^ssh$/i.test(title) || /^default \(ssh\)$/i.test(title);
}

/**
 * Activity label. Secure Input on a terminal buffer is the password-prompt case —
 * name it so it stacks with other credential timing anchors, without implying the
 * secret itself was recovered.
 */
function describeTerminalActivity(ev) {
  const secure = ev?.app?.secureInput === true;
  const ssh = windowLooksLikeSsh(ev);
  if (secure && ssh) return "SSH Session (Secure Input)";
  if (secure) return "Terminal Buffer (Secure Input)";
  if (ssh) return "SSH Session";
  return "Terminal Buffer";
}

function terminalBufferNote(ev) {
  const buf = extractTerminalBuffer(ev);
  const notes = [];
  if (buf.truncatedVisible) {
    notes.push("AX captured the VISIBLE terminal range only "
      + "(`[truncated to visible range]`) — not the full scrollback");
  }
  if (ev?.app?.secureInput === true) {
    notes.push("Secure Input was engaged: the typed password is withheld; "
      + "the command that opened the prompt is in Content");
  }
  return notes;
}

module.exports = {
  TERMINAL_VALUE_KIND,
  VISIBLE_RANGE_PREFIX,
  isTerminalValueChanged,
  extractTerminalBuffer,
  describeTerminalActivity,
  terminalBufferNote,
  windowLooksLikeSsh,
};
