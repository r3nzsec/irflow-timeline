/**
 * Canonical timestamp → milliseconds parser for DFIR analyzers.
 *
 * Replaces ad-hoc `Date.parse(s.replace(" ", "T"))` and `new Date(s).getTime()`
 * callsites that misparse "naive" timestamps (no TZ suffix) as host-local time
 * per ECMA-262, producing off-by-hours bugs on non-UTC analyst machines.
 *
 * Treats naive timestamps as UTC, which matches DFIR data conventions
 * (forensic timestamps in EVTX/MFT/USN are UTC unless the source explicitly
 * shifted them). ISO strings with a Z or +HH:MM offset are honored as written.
 *
 * Accepts:
 *   - number  → returned as-is if finite
 *   - Date    → .getTime()
 *   - string  → parsed; supported formats:
 *                 YYYY-MM-DD HH:MM:SS                  (naive — UTC)
 *                 YYYY-MM-DDTHH:MM:SS                  (naive — UTC)
 *                 YYYY-MM-DDTHH:MM:SSZ                 (UTC)
 *                 YYYY-MM-DDTHH:MM:SS+HH:MM            (offset — honored)
 *                 with optional .fff (3-7 digit fractional seconds)
 *
 * Returns: integer milliseconds since epoch, or null if unparseable.
 *
 * Usage:
 *   const { parseTimestampMs } = require("../utils/parse-timestamp");
 *   const ms = parseTimestampMs(row.timestamp);
 *   if (ms == null) return; // skip rows with bad timestamps
 */
function parseTimestampMs(value) {
  if (value == null) return null;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (value instanceof Date) {
    const t = value.getTime();
    return Number.isFinite(t) ? t : null;
  }
  const s = String(value).trim();
  if (!s) return null;
  // FILETIME epoch / DateTime.MinValue — not a real event time.
  if (/^(1600|1601|0001)[-/T]/.test(s)) return null;

  // Numeric epoch strings — SQLite TEXT columns are always strings, so an epoch column
  // arrives here as text. Mirrors forensic-normalize.normalizeTimestamp and the
  // sort_datetime SQL UDF so the timestamp utilities accept the same inputs:
  // 13 digits = ms epoch, 10 digits (optionally .fractional) = seconds epoch.
  if (/^\d{13}$/.test(s)) return parseInt(s, 10);
  if (/^\d{10}(\.\d+)?$/.test(s)) return Math.round(parseFloat(s) * 1000);

  // ISO with explicit TZ marker — Date.parse handles correctly. Honor Z, ±HH:MM,
  // ±HHMM, and hour-only ±HH (normalized to ±HH:00 so Date.parse doesn't silently
  // ignore the offset and fall through to the naive-UTC branch, shifting by hours).
  if (/Z$/.test(s)) {
    const ms = Date.parse(s);
    return Number.isFinite(ms) ? ms : null;
  }
  const offMatch = s.match(/([+-]\d{2})(:?\d{2})?$/);
  if (offMatch) {
    const ms = Date.parse(offMatch[2] ? s : s + ":00");
    return Number.isFinite(ms) ? ms : null;
  }

  // Naive timestamp → parse as UTC manually so a non-UTC host doesn't shift it.
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?/);
  if (!m) return null;
  const [, y, mo, d, h, mi, se, frac] = m;
  // Truncate sub-second precision to milliseconds (3 digits)
  const fracMs = frac ? Math.floor(Number("0." + frac) * 1000) : 0;
  const ms = Date.UTC(+y, +mo - 1, +d, +h, +mi, +se, fracMs);
  return Number.isFinite(ms) ? ms : null;
}

module.exports = { parseTimestampMs };
