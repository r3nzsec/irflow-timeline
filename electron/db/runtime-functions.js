const { registerForensicUDFs, normalizeTimestamp, isUnsetWindowsTimestamp } = require("../utils/forensic-normalize");
const { compileSafeRegex, MAX_VALUE_LEN, MAX_PATTERN_LEN } = require("../utils/safe-regex");

// Canonical, lexicographically-sortable UTC form ("YYYY-MM-DD HH:MM:SS.fff") for a value
// that carries an explicit timezone (Z or ±HH:MM). Mirrors the display path: the grid renders
// timestamp cells via normalizeTimestamp (naive = UTC, offsets honored), so sorting must use
// the same true instant or zoned rows (e.g. Hayabusa "+05:00" alongside naive EvtxECmd) sort
// by raw wall clock while the grid shows them converted — making the timeline look mis-sorted.
function zonedToCanonicalUtc(s) {
  const ms = normalizeTimestamp(s);
  if (!Number.isFinite(ms)) return null;
  const iso = new Date(ms).toISOString(); // YYYY-MM-DDTHH:MM:SS.fffZ
  return iso.slice(0, 10) + " " + iso.slice(11, 23);
}

// Windows FILETIME 0 and .NET DateTime.MinValue show up as 1601-01-01 / 0001-01-01
// in EvtxECmd/Hayabusa output. They are "timestamp not set", not real event times —
// including them in extract_date makes the histogram start in the 17th century.
function rejectUnsetWindowsTs(extracted) {
  if (extracted == null) return null;
  const s = String(extracted);
  if (/^(1600|1601|0001)-/.test(s)) return null;
  return extracted;
}

function hasExplicitZone(s) {
  return /[zZ]$|[+-]\d{2}:?\d{2}$/.test(s);
}

const MONTH_MAP = {
  jan: "01",
  feb: "02",
  mar: "03",
  apr: "04",
  may: "05",
  jun: "06",
  jul: "07",
  aug: "08",
  sep: "09",
  oct: "10",
  nov: "11",
  dec: "12",
};

// Last-resort parse for timestamp formats not matched by the explicit branches
// (month names like "Jul 3 2024", slash-ISO "2024/07/03", etc.). Date.parse() reads
// a naive (zone-less) string as HOST-LOCAL time, which shifts forensic timestamps on
// non-UTC analyst machines and makes them sort inconsistently against ISO rows. Force
// UTC by undoing that host-local offset when the string carries no explicit zone.
// Returns epoch ms, or NaN if unparseable / outside a plausible year range.
function looseParseUtcMs(s) {
  const hasZone = /[zZ]$|[+-]\d{2}:?\d{2}$|\b(?:UTC|GMT)\b/i.test(s);
  let t = Date.parse(s);
  if (Number.isNaN(t)) return NaN;
  if (!hasZone) t -= new Date(t).getTimezoneOffset() * 60000;
  const y = new Date(t).getUTCFullYear();
  return (y > 1970 && y < 2100) ? t : NaN;
}

function registerRuntimeFunctions(db) {
  // Bounded cache of compiled regex testers, keyed by pattern. A single query can emit
  // several distinct `REGEXP ?` conditions that SQLite evaluates interleaved per row; a
  // single-slot cache would recompile every pattern on every row (severe slowdown over
  // millions of rows). Invalid patterns cache as `null` so they short-circuit to 0.
  const _reCache = new Map();
  const RE_CACHE_MAX = 32;

  db.function("regexp", { deterministic: true }, (pattern, value) => {
    if (pattern == null || value == null) return 0;
    let tester = _reCache.get(pattern);
    if (tester === undefined) {
      const compiled = compileSafeRegex(pattern, "i");
      tester = compiled.error ? null : compiled.test;
      if (_reCache.size >= RE_CACHE_MAX) _reCache.delete(_reCache.keys().next().value);
      _reCache.set(pattern, tester);
    }
    if (!tester) return 0;
    try {
      return tester(value) ? 1 : 0;
    } catch {
      return 0;
    }
  });

  db.function("fuzzy_match", { deterministic: true }, (text, term) => {
    if (text == null || term == null) return 0;
    // Bound per-row work on giant cell values / search terms (DoS guard), mirroring
    // the caps applied to the `regexp` UDF via safe-regex.
    const t = String(text).slice(0, MAX_VALUE_LEN).toLowerCase();
    const s = String(term).slice(0, MAX_PATTERN_LEN).toLowerCase();
    if (t.includes(s)) return 1;
    if (s.length < 2) return 0;
    const n = s.length < 5 ? 2 : 3;
    const grams = [];
    for (let i = 0; i <= s.length - n; i++) grams.push(s.substring(i, i + n));
    if (grams.length === 0) return 0;
    let hits = 0;
    for (const g of grams) {
      if (t.includes(g)) hits++;
    }
    const threshold = s.length < 5 ? 0.7 : 0.6;
    return hits / grams.length >= threshold ? 1 : 0;
  });

  db.function("extract_date", { deterministic: true }, (val) => {
    if (val == null) return null;
    const s = String(val).trim();
    if (s.length >= 10 && s.charCodeAt(4) === 45 && s.charCodeAt(7) === 45 && s.charCodeAt(0) >= 48 && s.charCodeAt(0) <= 57) {
      // Zoned timestamps must bucket on the UTC date so the histogram matches
      // the TimeCreated column (which the grid renders in the selected TZ, default UTC).
      if (hasExplicitZone(s)) {
        const canonical = zonedToCanonicalUtc(s);
        if (canonical) return rejectUnsetWindowsTs(canonical.slice(0, 10));
      }
      return rejectUnsetWindowsTs(s.substring(0, 10));
    }
    let m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
    if (m) return `${m[3]}-${m[1].padStart(2, "0")}-${m[2].padStart(2, "0")}`;
    m = s.match(/^([A-Za-z]+)\s+(\d{1,2})\w*[\s,]+(\d{4})/);
    if (m) {
      const mo = MONTH_MAP[m[1].substring(0, 3).toLowerCase()];
      if (mo) return `${m[3]}-${mo}-${m[2].padStart(2, "0")}`;
    }
    m = s.match(/^(\d{1,2})[\s\-]([A-Za-z]+)[\s\-](\d{4})/);
    if (m) {
      const mo = MONTH_MAP[m[2].substring(0, 3).toLowerCase()];
      if (mo) return `${m[3]}-${mo}-${m[1].padStart(2, "0")}`;
    }
    if (/^\d{10}(\.\d+)?$/.test(s)) {
      const d = new Date(parseFloat(s) * 1000);
      if (!isNaN(d)) return d.toISOString().substring(0, 10);
    }
    if (/^\d{13}$/.test(s)) {
      const d = new Date(parseInt(s, 10));
      if (!isNaN(d)) return d.toISOString().substring(0, 10);
    }
    if (/^\d{1,5}(\.\d+)?$/.test(s)) {
      const serial = parseFloat(s);
      if (serial >= 1 && serial <= 73050) {
        const d = new Date(Math.round((serial - 25569) * 86400000));
        if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100) {
          return d.toISOString().substring(0, 10);
        }
      }
    }
    const t = looseParseUtcMs(s);
    if (Number.isFinite(t)) return new Date(t).toISOString().substring(0, 10);
    return null;
  });

  db.function("extract_datetime_minute", { deterministic: true }, (val) => {
    if (val == null) return null;
    const s = String(val).trim();
    if (s.length >= 16 && s.charCodeAt(4) === 45 && s.charCodeAt(7) === 45 && s.charCodeAt(0) >= 48 && s.charCodeAt(0) <= 57) {
      const sep = s.charCodeAt(10);
      if ((sep === 32 || sep === 84) && s.charCodeAt(13) === 58) {
        if (hasExplicitZone(s)) {
          const canonical = zonedToCanonicalUtc(s);
          if (canonical) {
            const day = rejectUnsetWindowsTs(canonical.slice(0, 10));
            if (!day) return null;
            return `${day} ${canonical.slice(11, 16)}`;
          }
        }
        const day = rejectUnsetWindowsTs(s.substring(0, 10));
        if (!day) return null;
        return `${day} ${s.substring(11, 16)}`;
      }
    }
    let m = s.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
    if (m) {
      const day = rejectUnsetWindowsTs(m[1]);
      if (!day) return null;
      return `${day} ${m[2]}`;
    }
    m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?/i);
    if (m) {
      let hh = parseInt(m[4], 10);
      if (m[7]) {
        const ap = m[7].toUpperCase();
        if (ap === "PM" && hh < 12) hh += 12;
        if (ap === "AM" && hh === 12) hh = 0;
      }
      return `${m[3]}-${m[1].padStart(2, "0")}-${m[2].padStart(2, "0")} ${String(hh).padStart(2, "0")}:${m[5]}`;
    }
    m = s.match(/^([A-Za-z]+)\s+(\d{1,2})\w*[\s,]+(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?/i);
    if (m) {
      const mo = MONTH_MAP[m[1].substring(0, 3).toLowerCase()];
      if (mo) {
        let hh = parseInt(m[4], 10);
        if (m[7]) {
          const ap = m[7].toUpperCase();
          if (ap === "PM" && hh < 12) hh += 12;
          if (ap === "AM" && hh === 12) hh = 0;
        }
        return `${m[3]}-${mo}-${m[2].padStart(2, "0")} ${String(hh).padStart(2, "0")}:${m[5]}`;
      }
    }
    m = s.match(/^(\d{1,2})[\s\-]([A-Za-z]+)[\s\-](\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?/i);
    if (m) {
      const mo = MONTH_MAP[m[2].substring(0, 3).toLowerCase()];
      if (mo) {
        let hh = parseInt(m[4], 10);
        if (m[7]) {
          const ap = m[7].toUpperCase();
          if (ap === "PM" && hh < 12) hh += 12;
          if (ap === "AM" && hh === 12) hh = 0;
        }
        return `${m[3]}-${mo}-${m[1].padStart(2, "0")} ${String(hh).padStart(2, "0")}:${m[5]}`;
      }
    }
    m = s.match(/^([A-Za-z]+)\s+(\d{1,2})\w*[\s,]+(\d{4})/);
    if (m) {
      const mo = MONTH_MAP[m[1].substring(0, 3).toLowerCase()];
      if (mo) return `${m[3]}-${mo}-${m[2].padStart(2, "0")} 00:00`;
    }
    m = s.match(/^(\d{1,2})[\s\-]([A-Za-z]+)[\s\-](\d{4})/);
    if (m) {
      const mo = MONTH_MAP[m[2].substring(0, 3).toLowerCase()];
      if (mo) return `${m[3]}-${mo}-${m[1].padStart(2, "0")} 00:00`;
    }
    if (/^\d{1,5}(\.\d+)?$/.test(s)) {
      const serial = parseFloat(s);
      if (serial >= 1 && serial <= 73050) {
        const d = new Date((serial - 25569) * 86400000);
        if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100) {
          const iso = d.toISOString();
          return `${iso.substring(0, 10)} ${iso.substring(11, 16)}`;
        }
      }
    }
    const t = looseParseUtcMs(s);
    if (Number.isFinite(t)) {
      const iso = new Date(t).toISOString();
      return `${iso.substring(0, 10)} ${iso.substring(11, 16)}`;
    }
    return null;
  });

  db.function("sort_datetime", { deterministic: true }, (val) => {
    if (val == null || val === "") return null;
    const s = String(val).trim();
    if (isUnsetWindowsTimestamp(s)) return null;
    if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s)) {
      // Honor an explicit timezone so the value sorts on the same true-instant basis the
      // grid display uses. A naive string keeps its wall clock (treated as UTC) at full
      // precision; a zoned string is converted to canonical UTC so it can't sort by raw
      // local wall clock against naive rows.
      if (/[zZ]$|[+-]\d{2}:?\d{2}$/.test(s)) {
        const canonical = zonedToCanonicalUtc(s);
        if (canonical) return canonical;
      }
      return s.replace("T", " ");
    }
    if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s + " 00:00:00";
    let m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\s*(.*)/);
    if (m) {
      let timePart = m[4] || "00:00:00";
      const ampm = timePart.match(/\s*([AP]M)\s*$/i);
      timePart = timePart.replace(/\s*[AP]M\s*$/i, "").trim();
      if (ampm && timePart) {
        const tp = timePart.split(":");
        let h = parseInt(tp[0], 10) || 0;
        if (/PM/i.test(ampm[1]) && h !== 12) h += 12;
        if (/AM/i.test(ampm[1]) && h === 12) h = 0;
        tp[0] = String(h).padStart(2, "0");
        timePart = tp.join(":");
      }
      return `${m[3]}-${m[1].padStart(2, "0")}-${m[2].padStart(2, "0")} ${timePart || "00:00:00"}`;
    }
    if (/^\d{10}(\.\d+)?$/.test(s)) {
      const d = new Date(parseFloat(s) * 1000);
      if (!isNaN(d)) return d.toISOString().replace("T", " ").replace("Z", "");
    }
    if (/^\d{13}$/.test(s)) {
      const d = new Date(parseInt(s, 10));
      if (!isNaN(d)) return d.toISOString().replace("T", " ").replace("Z", "");
    }
    if (/^\d{1,5}(\.\d+)?$/.test(s)) {
      const serial = parseFloat(s);
      if (serial >= 1 && serial <= 73050) {
        const d = new Date(Math.round((serial - 25569) * 86400000));
        if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100) {
          return d.toISOString().replace("T", " ").replace("Z", "");
        }
      }
    }
    const t = looseParseUtcMs(s);
    if (Number.isFinite(t)) {
      return new Date(t).toISOString().replace("T", " ").replace("Z", "");
    }
    return s;
  });

  registerForensicUDFs(db);
}

module.exports = { registerRuntimeFunctions };
