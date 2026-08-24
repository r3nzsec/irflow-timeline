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

export function normalizeTimestamp(value) {
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
