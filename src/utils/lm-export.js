/**
 * lm-export.js — export-safety helpers for the Lateral Movement Tracker.
 *
 * Pure functions, no React or Electron, so they can be unit-tested directly.
 *
 * Two problems these exist to solve:
 *
 *  1. The evidence package wrote complete raw source rows to disk. Lateral-movement
 *     evidence is exactly the material most likely to carry credentials — `net use
 *     /user:`, `psexec -p`, `runas`, connection strings — so an "export the evidence"
 *     button was a credential-exfiltration path by default.
 *
 *  2. Three separate CSV escapers existed and none neutralised formula injection. Every
 *     exported Title / Description / Why-Flagged field is derived from event data
 *     including command lines, so a row beginning `=cmd|...` executes on open in Excel.
 */

const MASK = "***REDACTED***";

// A quoted, single-quoted, or bare token — the thing being masked.
const VALUE = String.raw`"[^"]*"|'[^']*'|[^\s,;|]+`;

// NOTE on anchoring: `\b` does NOT match between a space and a `-`, because neither is a
// word character. Flag-style patterns must therefore anchor on `(^|\s)` rather than `\b`,
// and alternations are ordered longest-first so `--password=` is not consumed as `-p`.
//
// Each entry keeps the flag/key visible — that a credential was supplied is itself
// evidence — and masks only the value.
const SECRET_PATTERNS = [
  // -hashes LM:NT  (before the generic flag rule, which would otherwise stop at -h)
  { re: new RegExp(String.raw`((?:^|\s)[-/]{1,2}hashes?[\s:=]+)(${VALUE})`, "gi") },
  // -EncodedCommand <base64>
  { re: new RegExp(String.raw`((?:^|\s)[-/]{1,2}(?:encodedcommand|enc|ec|e)\s+)([A-Za-z0-9+/=]{40,})`, "gi") },
  // -p Pa$$w0rd  /  /P:secret  /  --password=...  /  -pwd ...  /  -Token abc123
  { re: new RegExp(String.raw`((?:^|\s)[-/]{1,2}(?:password|passwd|pwd|pass|token|secret|apikey|api[_-]?key|p)[\s:=]+)(${VALUE})`, "gi") },
  // password=... / pwd: ... / secret = ... inside a connection string or KV blob
  { re: new RegExp(String.raw`(\b(?:password|passwd|pwd|secret|apikey|api[_-]?key|token|credential)\b\s*[:=]\s*)(${VALUE})`, "gi") },
  // A bare LM:NT hash pair anywhere in the text — the whole match is the secret.
  { re: /\b[a-f0-9]{32}:[a-f0-9]{32}\b/gi, whole: true },
];

/**
 * Mask credential-bearing values inside a free-text string.
 * Returns the input unchanged when there is nothing to mask.
 */
export function redactSecrets(value) {
  if (value == null) return value;
  let s = String(value);
  if (!s) return s;
  for (const { re, whole } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    s = s.replace(re, (match, prefix) => (whole ? MASK : `${prefix}${MASK}`));
  }
  return s;
}

/** Apply redactSecrets to every string value, including nested objects/arrays. */
export function redactRow(row) {
  if (row == null) return row;
  if (typeof row === "string") return redactSecrets(row);
  if (Array.isArray(row)) return row.map(redactRow);
  if (typeof row !== "object") return row;
  const out = {};
  for (const [k, v] of Object.entries(row)) out[k] = redactRow(v);
  return out;
}

/**
 * Render one CSV cell: RFC-4180 quoting plus formula-injection neutralisation.
 *
 * A leading =, +, -, @, tab or CR makes Excel/Sheets/Numbers treat the cell as a
 * formula. Prefixing a single quote keeps the text readable while making it inert.
 */
export function csvCell(value) {
  const s = value == null ? "" : String(value);
  const neutralised = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${neutralised.replace(/"/g, '""')}"`;
}

/** Build a CSV document from an array of arrays (first row is usually the header). */
export function toCSV(rows) {
  return (rows || []).map((r) => (r || []).map(csvCell).join(",")).join("\n");
}

export const REDACTION_MASK = MASK;
