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

// Returns epoch milliseconds for any timestamp value the importer might see.
// Returns NaN if unparseable. Mirrors the format coverage of sort_datetime in db.js.
function normalizeTimestamp(value) {
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
  // US date M/D/YYYY [HH:MM[:SS] [AM/PM]]
  let m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?)?/i);
  if (m) {
    let h = parseInt(m[4] || "0", 10);
    const ap = m[7];
    if (ap) {
      if (/PM/i.test(ap) && h !== 12) h += 12;
      if (/AM/i.test(ap) && h === 12) h = 0;
    }
    const iso = `${m[3]}-${m[1].padStart(2, "0")}-${m[2].padStart(2, "0")}T${String(h).padStart(2, "0")}:${m[5] || "00"}:${m[6] || "00"}Z`;
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
