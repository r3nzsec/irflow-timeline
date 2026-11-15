import { normalizeTimestamp, timestampFraction } from "./forensic-normalize.js";

// HTML datetime-local controls accept T-separated values and at most milliseconds.
// Convert for display only: keep the full-precision UTC bound unless the user edits it.
export function dateRangeInputValue(value) {
  if (!value) return "";
  const ms = normalizeTimestamp(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 23) : "";
}

/** Clear filter state, preserving the underlying bookmarks, tags and evidence. */
export function clearedFiltersPatch() {
  return {
    searchTerm: "", columnFilters: {}, checkboxFilters: {},
    dateRangeFilters: {}, advancedFilters: [], showBookmarkedOnly: false,
    tagFilter: null, rowIdFilter: null, rowIdFilterLabel: null,
    searchHighlight: false, disabledFilters: new Set(),
  };
}

/** Build one atomic tab update for the selected timestamp's inclusive time window. */
export function buildProximityFilter(tab, tsCol, pivotRaw, windowMs, label, removeFilters = false) {
  if (!tab?.tsColumns?.has(tsCol)) return { error: "Select a timestamp column." };
  if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
    return { error: "Choose a positive time window in whole milliseconds." };
  }
  // Hayabusa's default timestamp has a space before its UTC offset. Replacing
  // just the first space with T makes Date.parse reject it. Use the same parser
  // as the grid, honoring explicit offsets and treating naive timestamps as UTC.
  const pivotMs = normalizeTimestamp(pivotRaw);
  if (!Number.isFinite(pivotMs)) return { error: "The selected timestamp could not be read. Choose another timestamp column or row." };
  const from = new Date(pivotMs - windowMs);
  const to = new Date(pivotMs + windowMs);
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime())
    || from.getUTCFullYear() < 1 || to.getUTCFullYear() > 9999) {
    return { error: "The time window is too large. Choose a smaller window." };
  }
  // Whole-millisecond shifts leave the source's sub-millisecond digits intact.
  const tail = timestampFraction(pivotRaw).slice(3);
  const format = (d, upper) => {
    const iso = d.toISOString();
    const whole = iso.slice(0, 19).replace("T", " ");
    const fraction = (iso.slice(20, 23) + tail).padEnd(9, "0");
    // Sort keys retain source precision. Include equal instants at either end
    // whether a row writes no fraction, .000, or .000000000.
    const digits = upper ? fraction : fraction.replace(/0+$/, "");
    return whole + (digits ? "." + digits : "");
  };
  return {
    tabPatch: {
      ...(removeFilters ? clearedFiltersPatch() : {}),
      dateRangeFilters: {
        ...(removeFilters ? {} : tab.dateRangeFilters),
        [tsCol]: { from: format(from, false), to: format(to, true) },
      },
    },
    proximity: { tsCol, pivotRaw: String(pivotRaw), windowMs, label },
  };
}
