// Canonical forensic value normalizers (ESM — renderer / Vite).
//
// Mirrors electron/utils/forensic-normalize.js (CJS) — keep both files in lockstep.
// Tests in tests/forensic-normalize.test.js exercise the backend copy; this file
// must produce identical results for every input.
//
// See the backend copy for rationale. The renderer uses these in clustering, story
// grouping, and the Process Inspector evidence pipeline so that timestamp parsing,
// GUID matching, and host scoping behave the same on both sides of IPC.

export function isUnsetWindowsTimestamp(value) {
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

export function parseNumericDate(value, dayFirst = false) {
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
export function numericDateIso(d) {
  const ms = d.fraction ? "." + d.fraction.slice(0, 3).padEnd(3, "0") : "";
  return `${d.year}-${d.month}-${d.day}T${d.hour}:${d.minute}:${d.second}${ms}${d.zone || "Z"}`;
}

// options.dayFirst reads ambiguous numeric dates day first (a European-format column).
export function normalizeTimestamp(value, options = {}) {
  if (value == null || value === "") return NaN;
  const s = String(value).trim();
  if (!s) return NaN;
  if (isUnsetWindowsTimestamp(s)) return NaN;

  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s)) {
    const iso = s.replace(" ", "T");
    const t = Date.parse(/[zZ]|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : iso + "Z");
    if (!Number.isNaN(t)) return t;
  }
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
  if (/^\d{10}(\.\d+)?$/.test(s)) return parseFloat(s) * 1000;
  if (/^\d{13}$/.test(s)) return parseInt(s, 10);
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

export function compareTimestamps(a, b) {
  const ta = normalizeTimestamp(a);
  const tb = normalizeTimestamp(b);
  const av = Number.isFinite(ta) ? ta : Number.MAX_SAFE_INTEGER;
  const bv = Number.isFinite(tb) ? tb : Number.MAX_SAFE_INTEGER;
  return av - bv;
}

export function normalizeGuid(value) {
  if (value == null) return "";
  return String(value).trim().replace(/[{}]/g, "").toLowerCase();
}

export function normalizePid(value) {
  if (value == null) return "";
  const s = String(value).trim();
  if (!s) return "";
  if (/^0x[0-9a-f]+$/i.test(s)) return String(parseInt(s, 16));
  const m = s.match(/-?\d+/);
  return m ? m[0] : "";
}

export function normalizeLogonId(value) {
  if (value == null) return "";
  const s = String(value).trim();
  if (!s) return "";
  if (/^0x[0-9a-f]+$/i.test(s)) return String(parseInt(s, 16));
  const m = s.match(/^-?\d+$/);
  if (m) return m[0];
  const hex = s.match(/0x[0-9a-f]+/i);
  if (hex) return String(parseInt(hex[0], 16));
  const dec = s.match(/\d+/);
  return dec ? dec[0] : s.toLowerCase();
}

export function normalizeHost(value) {
  if (value == null) return "";
  return String(value).trim().replace(/^\\\\/, "").toUpperCase();
}

export function normalizeUser(value) {
  if (value == null) return "";
  let s = String(value).trim();
  if (!s) return "";
  if (s.includes("\\")) s = s.split("\\").pop();
  return s.toLowerCase();
}
