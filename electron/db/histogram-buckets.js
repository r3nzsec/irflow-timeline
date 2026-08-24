const { parseTimestampMs } = require("../utils/parse-timestamp");

// Windows FILETIME 0 / .NET DateTime.MinValue — not real event times.
const UNSET_YEAR_RE = /^(1600|1601|0001)-/;
// Fill empty day/hour buckets so the x-axis is a real calendar, not a sparse
// list of dates-with-events (which parks 1601-01-01 next to last week's logs).
const MAX_FILL_BUCKETS = 4000;

function isUnsetWindowsBucket(day) {
  return typeof day === "string" && UNSET_YEAR_RE.test(day);
}

function bucketToMs(day, isHourly) {
  if (!day) return null;
  if (isHourly) {
    const s = String(day).length === 13 ? `${day}:00:00` : String(day);
    return parseTimestampMs(s);
  }
  const raw = String(day);
  const s = raw.length === 10 ? `${raw} 00:00:00` : raw;
  return parseTimestampMs(s);
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function msToBucket(ms, isHourly) {
  const d = new Date(ms);
  const day = `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
  if (!isHourly) return day;
  return `${day} ${pad2(d.getUTCHours())}`;
}

/**
 * Drop FILETIME-epoch sentinel buckets and fill gaps between the first and last
 * real bucket so histogram range/labels match the TimeCreated column.
 */
function fillHistogramGaps(rows, granularity = "day") {
  if (!Array.isArray(rows) || rows.length === 0) return [];
  const cleaned = [];
  for (const r of rows) {
    if (!r || r.day == null || r.day === "") continue;
    if (isUnsetWindowsBucket(String(r.day))) continue;
    cleaned.push({ day: r.day, cnt: Number(r.cnt) || 0 });
  }
  if (cleaned.length <= 1) return cleaned;

  const isHourly = granularity === "hour";
  const stepMs = isHourly ? 3600000 : 86400000;
  const startMs = bucketToMs(cleaned[0].day, isHourly);
  const endMs = bucketToMs(cleaned[cleaned.length - 1].day, isHourly);
  if (startMs == null || endMs == null || endMs < startMs) return cleaned;

  const n = Math.floor((endMs - startMs) / stepMs) + 1;
  if (!Number.isFinite(n) || n <= cleaned.length || n > MAX_FILL_BUCKETS) return cleaned;

  const map = new Map();
  for (const r of cleaned) map.set(r.day, r.cnt);

  const filled = new Array(n);
  for (let i = 0; i < n; i++) {
    const day = msToBucket(startMs + i * stepMs, isHourly);
    filled[i] = { day, cnt: map.get(day) || 0 };
  }
  return filled;
}

module.exports = {
  fillHistogramGaps,
  isUnsetWindowsBucket,
  MAX_FILL_BUCKETS,
};
