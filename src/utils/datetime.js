import { isUnsetWindowsTimestamp, normalizeTimestamp } from "./forensic-normalize.js";

export const UNSET_TIMESTAMP_LABEL = "Unset";
export const UNSET_TIMESTAMP_TITLE = "Unset timestamp (Windows FILETIME epoch 1601-01-01 — not a real event time)";

const _dtfCache = {};
function _getCachedDtf(tz) {
  if (!_dtfCache[tz]) {
    _dtfCache[tz] = new Intl.DateTimeFormat("en-US", {
      timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
  }
  return _dtfCache[tz];
}

export function formatDateTime(raw, fmt, tz) {
  if (!raw && raw !== 0) return raw || "";
  if (isUnsetWindowsTimestamp(raw)) return UNSET_TIMESTAMP_LABEL;
  if (!fmt) return raw || "";
  // Parse via the canonical normalizer so naive (zone-less) timestamps are read as
  // UTC — the convention the backend and every analysis modal use. Plain new Date(raw)
  // treats them as host-local, showing grid times shifted from the analysis panels.
  const ms = normalizeTimestamp(raw);
  if (!Number.isFinite(ms)) return raw;
  const d = new Date(ms);
  let Y, M, D, h, m, s;
  if (!tz || tz === "local") {
    Y = d.getFullYear(); M = String(d.getMonth() + 1).padStart(2, "0");
    D = String(d.getDate()).padStart(2, "0"); h = String(d.getHours()).padStart(2, "0");
    m = String(d.getMinutes()).padStart(2, "0"); s = String(d.getSeconds()).padStart(2, "0");
  } else {
    const parts = {};
    for (const { type, value } of _getCachedDtf(tz).formatToParts(d)) parts[type] = value;
    Y = parts.year; M = parts.month; D = parts.day;
    h = parts.hour === "24" ? "00" : parts.hour; m = parts.minute; s = parts.second;
  }
  const ms3 = String(d.getMilliseconds()).padStart(3, "0");
  const us7 = ms3 + "0000";
  return fmt
    .replace("yyyy", Y).replace("MM", M).replace("dd", D)
    .replace("HH", h).replace("mm", m).replace("ss", s)
    .replace("fffffff", us7).replace("fff", ms3);
}
