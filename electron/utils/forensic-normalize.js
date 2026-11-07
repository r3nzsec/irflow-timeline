// Canonical forensic value normalizers (CJS — main process / analyzers).
//
// Mirrors src/utils/forensic-normalize.js (ESM) — keep both files in lockstep.
// Tests in tests/forensic-normalize.test.js exercise these against the renderer copy.
//
// Purpose: every place that compares timestamps, GUIDs, PIDs, logon IDs, hostnames,
// or usernames must funnel through these helpers. The repo previously normalized the
// same concept in 4+ places with subtle drift (raw new Date(), brace-sensitive GUIDs,
// hex logon IDs treated as strings) which produced silent correlation misses and
// fabricated cross-host process chains.
//
// SQL-side parity: registerForensicUDFs(db) adds norm_guid() and norm_logon_id()
// that mirror normalizeGuid / normalizeLogonId so WHERE clauses can normalize the
// column side without per-query LOWER/REPLACE noise.

// ---------- Timestamp ----------

// Windows FILETIME 0 and .NET DateTime.MinValue. EvtxECmd/Hayabusa render a zero
// TimeCreated as 1601-01-01 (or 1600-12-31 if a positive offset was applied).
// These are "timestamp not set", not real event times.
function isUnsetWindowsTimestamp(value) {
  if (value == null || value === "") return false;
  const s = String(value).trim();
  if (!s) return false;
  return /^(1600|1601|0001)[-/T]/.test(s);
}

// Numeric dates: M/D/YYYY or M-D-YYYY (US), or D-M-YYYY (European), with an optional time
// (24- or 12-hour, fractional seconds) and UTC offset, as Hayabusa's --us-time,
// --us-military-time and --european-time write them ("08-31-2017 04:13:38.198 PM +09:00",
// "31-08-2017 04:13:38.198 +09:00"). The first number is the month unless `dayFirst` is set
// (a column found to be day-first) or it can only be a day (over 12).
const NUMERIC_DATE_RE = /^(\d{1,2})[\/.-](\d{1,2})[\/.-](\d{4})(?:[ T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?(?:\s*([AP]M))?(?:\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2}))?)?$/i;

function parseNumericDate(value, dayFirst = false) {
  if (value == null) return null;
  const m = NUMERIC_DATE_RE.exec(String(value).trim());
  if (!m) return null;
  const a = parseInt(m[1], 10);
  const b = parseInt(m[2], 10);
  const dayIsFirst = dayFirst || (a > 12 && b <= 12);
  const month = dayIsFirst ? b : a;
  const day = dayIsFirst ? a : b;
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  let hour = m[4] == null ? 0 : parseInt(m[4], 10);
  const ampm = m[8] ? m[8].toUpperCase() : "";
  if (ampm) {
    if (hour < 1 || hour > 12) return null;
    if (ampm === "PM" && hour !== 12) hour += 12;
    if (ampm === "AM" && hour === 12) hour = 0;
  }
  if (hour > 23) return null;
  let zone = m[9] || "";
  if (/^(Z|UTC|GMT)$/i.test(zone)) zone = "Z";
  else if (zone && !zone.includes(":")) zone = `${zone.slice(0, 3)}:${zone.slice(3)}`;
  const pad = (n) => String(n).padStart(2, "0");
  return {
    year: m[3], month: pad(month), day: pad(day), hour: pad(hour),
    minute: m[5] || "00", second: m[6] || "00", fraction: m[7] || "", zone,
  };
}

// ISO 8601 text for a parseNumericDate() result (UTC when it has no offset), millisecond precision.
function numericDateIso(d) {
  const ms = d.fraction ? "." + d.fraction.slice(0, 3).padEnd(3, "0") : "";
  return `${d.year}-${d.month}-${d.day}T${d.hour}:${d.minute}:${d.second}${ms}${d.zone || "Z"}`;
}

// Returns epoch milliseconds for any timestamp value the importer might see.
// Returns NaN if unparseable. Mirrors the format coverage of sort_datetime in db.js.
// options.dayFirst reads ambiguous numeric dates day first (a European-format column).
function normalizeTimestamp(value, options = {}) {
  if (value == null || value === "") return NaN;
  const s = String(value).trim();
  if (!s) return NaN;
  if (isUnsetWindowsTimestamp(s)) return NaN;

  // Fast path: ISO 8601 (most forensic data)
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s)) {
    const iso = s.replace(" ", "T");
    const t = Date.parse(/[zZ]|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : iso + "Z");
    if (!Number.isNaN(t)) return t;
  }
  // ISO date-only
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    const t = Date.parse(s + "T00:00:00Z");
    if (!Number.isNaN(t)) return t;
  }
  // Numeric dates (US, US military, European), with fractions, AM/PM and offsets
  const nd = parseNumericDate(s, options?.dayFirst);
  if (nd) {
    const t = Date.parse(numericDateIso(nd));
    if (!Number.isNaN(t)) return t;
  }
  // US date M/D/YYYY [HH:MM[:SS] [AM/PM]] followed by other text
  let m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?)?/i);
  if (m) {
    let h = parseInt(m[4] || "0", 10);
    const ap = m[7];
    if (ap) {
      if (/PM/i.test(ap) && h !== 12) h += 12;
      if (/AM/i.test(ap) && h === 12) h = 0;
    }
    const swap = options?.dayFirst || (parseInt(m[1], 10) > 12 && parseInt(m[2], 10) <= 12);
    const [mo, dd] = swap ? [m[2], m[1]] : [m[1], m[2]];
    const iso = `${m[3]}-${mo.padStart(2, "0")}-${dd.padStart(2, "0")}T${String(h).padStart(2, "0")}:${m[5] || "00"}:${m[6] || "00"}Z`;
    const t = Date.parse(iso);
    if (!Number.isNaN(t)) return t;
  }
  // Unix seconds (10 digits) or millis (13 digits)
  if (/^\d{10}(\.\d+)?$/.test(s)) return parseFloat(s) * 1000;
  if (/^\d{13}$/.test(s)) return parseInt(s, 10);
  // Excel serial date
  if (/^\d{1,5}(\.\d+)?$/.test(s)) {
    const serial = parseFloat(s);
    if (serial >= 1 && serial <= 73050) {
      const ms = Math.round((serial - 25569) * 86400000);
      const y = new Date(ms).getUTCFullYear();
      if (y >= 1900 && y <= 2100) return ms;
    }
  }
  // Last-resort: a wide range of locale formats (month names like "Jul 3 2024",
  // slash-ISO "2024/07/03", etc.). Date.parse() treats a naive (zone-less) string
  // as HOST-LOCAL time per ECMA-262, which silently shifts forensic timestamps on
  // non-UTC analyst machines. Force UTC: parse, then undo the host-local offset
  // Date.parse applied when the string carried no explicit zone.
  const hasZone = /[zZ]$|[+-]\d{2}:?\d{2}$|\b(?:UTC|GMT)\b/i.test(s);
  let t = Date.parse(s);
  if (!Number.isNaN(t)) {
    if (!hasZone) t -= new Date(t).getTimezoneOffset() * 60000;
    const y = new Date(t).getUTCFullYear();
    if (y > 1970 && y < 2100) return t;
  }
  return NaN;
}

// Compare two timestamp values without trusting raw lexical ordering.
// Returns negative if a<b, positive if a>b, 0 if equal-or-both-unknown.
// Unknown values sort AFTER known values (Number.MAX_SAFE_INTEGER).
function compareTimestamps(a, b) {
  const ta = normalizeTimestamp(a);
  const tb = normalizeTimestamp(b);
  const av = Number.isFinite(ta) ? ta : Number.MAX_SAFE_INTEGER;
  const bv = Number.isFinite(tb) ? tb : Number.MAX_SAFE_INTEGER;
  return av - bv;
}

// ---------- GUID ----------

// Returns lowercase hex GUID with no braces / whitespace. Empty string if not a GUID-like value.
function normalizeGuid(value) {
  if (value == null) return "";
  const s = String(value).trim().replace(/[{}]/g, "").toLowerCase();
  // Accept anything containing a hex/dash sequence — keep as-is once cleaned
  return s;
}

// ---------- PID / PPID ----------

// Returns the integer-as-string form of a PID.
// Handles "0x1a2c" hex, "1234", " 1234 ", and embedded values like "ProcessID: 1234".
function normalizePid(value) {
  if (value == null) return "";
  const s = String(value).trim();
  if (!s) return "";
  if (/^0x[0-9a-f]+$/i.test(s)) return String(parseInt(s, 16));
  const m = s.match(/-?\d+/);
  return m ? m[0] : "";
}

// ---------- Logon ID ----------

// Returns the canonical decimal form of a Windows logon ID.
// Security 4624/4672 may emit "0x3e7" while Sysmon and many parsers emit "999".
// Without normalization those never join.
function normalizeLogonId(value) {
  if (value == null) return "";
  const s = String(value).trim();
  if (!s) return "";
  if (/^0x[0-9a-f]+$/i.test(s)) return String(parseInt(s, 16));
  const m = s.match(/^-?\d+$/);
  if (m) return m[0];
  // Embedded form like "LogonId: 0x3e7" — try to recover
  const hex = s.match(/0x[0-9a-f]+/i);
  if (hex) return String(parseInt(hex[0], 16));
  const dec = s.match(/\d+/);
  return dec ? dec[0] : s.toLowerCase();
}

// ---------- Hostname ----------

// Returns trimmed-uppercase hostname. Empty string if absent.
// Strips leading "\\" UNC prefix. Does NOT fall back to a user's domain — Finding #4
// proved that fallback collapses multiple endpoints into one fake "incident".
function normalizeHost(value) {
  if (value == null) return "";
  const s = String(value).trim().replace(/^\\\\/, "");
  return s.toUpperCase();
}

// ---------- User ----------

// Returns lowercase username with DOMAIN\ prefix stripped.
function normalizeUser(value) {
  if (value == null) return "";
  let s = String(value).trim();
  if (!s) return "";
  if (s.includes("\\")) s = s.split("\\").pop();
  return s.toLowerCase();
}

// ---------- SQL UDFs ----------

// Registers norm_guid and norm_logon_id on a better-sqlite3 Database instance.
// Idempotent: safe to call multiple times. Used by db.js so any analyzer can write
// `WHERE norm_guid(col) = ?` instead of LOWER(REPLACE(REPLACE(...))) per query.
function registerForensicUDFs(db) {
  if (!db || typeof db.function !== "function") return;
  try {
    db.function("norm_guid", { deterministic: true }, (val) => normalizeGuid(val));
  } catch (_) { /* already registered */ }
  try {
    db.function("norm_logon_id", { deterministic: true }, (val) => normalizeLogonId(val));
  } catch (_) { /* already registered */ }
  try {
    db.function("norm_host", { deterministic: true }, (val) => normalizeHost(val));
  } catch (_) { /* already registered */ }
  try {
    db.function("norm_pid", { deterministic: true }, (val) => normalizePid(val));
  } catch (_) { /* already registered */ }
}

module.exports = {
  parseNumericDate,
  numericDateIso,
  normalizeTimestamp,
  isUnsetWindowsTimestamp,
  compareTimestamps,
  normalizeGuid,
  normalizePid,
  normalizeLogonId,
  normalizeHost,
  normalizeUser,
  registerForensicUDFs,
};
