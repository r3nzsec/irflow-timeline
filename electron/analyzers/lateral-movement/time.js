/**
 * time.js — timestamp helpers for the lateral-movement analyzer.
 *
 * Every timestamp compare, sort and gap calculation in this subsystem must go
 * through here. Three classes of bug motivated it:
 *
 *  1. String ordering. `"2026-01-02 08:00:00" < "2026-01-02T09:00:00"` is TRUE
 *     for the space form and FALSE for the "T" form of the same instant, because
 *     0x20 sorts before "T". On a multi-source merge (EvtxECmd writes a space,
 *     raw EVTX writes a "T") that put every EvtxECmd row of a day ahead of every
 *     raw row of the same day, corrupting chains, brute-force windows and the
 *     auth -> share -> exec sequencer.
 *  2. Mixed naive/ISO compares. A threshold produced by `toISOString()` compared
 *     against a naive column value is the same bug with a different origin.
 *  3. `new Date(naive)` is HOST-LOCAL per ECMA-262, so every gap in minutes moved
 *     with the analyst's timezone and broke across their DST change.
 *
 * normalizeTimestamp() is the canonical parser (naive == UTC) and is shared with
 * the importer and the renderer, so the analyzer now orders events exactly the
 * way the grid does.
 */

const { normalizeTimestamp } = require("../../utils/forensic-normalize");

/** Epoch ms for a timestamp value, or null when unparseable/unset. */
function tsMs(value) {
  const parsed = normalizeTimestamp(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Chronological comparator. Parseable values always order before unparseable
 * ones (which fall back to a stable lexical compare among themselves) so a few
 * malformed rows cannot reshuffle the good ones.
 */
function cmpTs(a, b) {
  const am = tsMs(a);
  const bm = tsMs(b);
  if (am != null && bm != null) return am - bm;
  if (am != null) return -1;
  if (bm != null) return 1;
  return String(a == null ? "" : a).localeCompare(String(b == null ? "" : b));
}

/** In-place chronological sort by a timestamp-valued key (default `ts`). */
function sortByTs(arr, key = "ts") {
  return arr.sort((a, b) => cmpTs(a && a[key], b && b[key]));
}

/** The earlier of two timestamp values, keeping the original string form. */
function earlierTs(a, b) {
  if (a == null || a === "") return b;
  if (b == null || b === "") return a;
  return cmpTs(a, b) <= 0 ? a : b;
}

/** The later of two timestamp values, keeping the original string form. */
function laterTs(a, b) {
  if (a == null || a === "") return b;
  if (b == null || b === "") return a;
  return cmpTs(a, b) >= 0 ? a : b;
}

/** Signed gap in ms between two timestamps (b - a), or null if either is unparseable. */
function gapMs(a, b) {
  const am = tsMs(a);
  const bm = tsMs(b);
  return am != null && bm != null ? bm - am : null;
}

module.exports = { tsMs, cmpTs, sortByTs, earlierTs, laterTs, gapMs };
