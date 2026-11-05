// Column widths for View → Full-width cells and
// View → Narrow-width cells.
//
// Full-width makes every column as wide as its widest entry. Narrow-width does the same but
// stops at NARROW_MAX_CHARS characters, so a column of short values takes no more room than
// they need and a column of long ones takes 30 characters. The header counts as an entry, so
// a column is never narrower than its name (in narrow mode, up to the same limit).
//
// Widths come from the text as the grid shows it (fmt reformats timestamps), measured with the
// grid's own fonts by the measureCell / measureHeader callbacks.

export const NARROW_MAX_CHARS = 30;

const CELL_PADDING = 16; // every cell and header has padding: 0 8px
const BORDER = 1; // the right border of each cell
const SLACK = 2; // subpixel rounding: the widest value must not end in an ellipsis
const MIN_WIDTH = 40; // keeps the filter box and the resize handle usable
const PIN_BUTTON = 27; // the 📌 button of a pinned column's header (24 px + 3 px margin)

/**
 * @param {object} p
 * @param {string[]} p.headers                columns to size
 * @param {Record<string, {maxLen: number, longest: string|null}>} p.longest  from getColumnLongestValues
 * @param {"full"|"narrow"} p.mode
 * @param {(header: string, value: string) => string} p.fmt  text the grid shows for a value
 * @param {(text: string) => number} p.measureCell    width of cell text in px
 * @param {(text: string) => number} p.measureHeader  width of header text in px
 * @param {Set<string>} [p.tsColumns]         timestamp columns (their header shows ⏱)
 * @param {string|null} [p.sortCol]           sorted column (its header shows ▲ or ▼)
 * @param {string[]} [p.pinnedColumns]
 * @returns {Record<string, number>} width in px per header
 */
export function computeCellWidths({
  headers, longest, mode, fmt, measureCell, measureHeader,
  tsColumns = new Set(), sortCol = null, pinnedColumns = [],
}) {
  const charWidth = measureCell("0");
  const cap = measureCell("0".repeat(NARROW_MAX_CHARS));
  const box = (px) => Math.ceil(px) + CELL_PADDING + BORDER + SLACK;
  const widths = {};
  for (const h of headers) {
    const info = longest?.[h] || { maxLen: 0, longest: null };
    let content = 0;
    if (info.longest != null && info.longest !== "") content = measureCell(String(fmt(h, info.longest) ?? ""));
    else if (info.maxLen > 0) content = info.maxLen * charWidth; // too long to send: monospace estimate

    let header = measureHeader(h);
    if (tsColumns.has(h)) header += measureHeader("⏱") + 2;
    if (sortCol === h) header += measureHeader("▲") + 3;
    if (pinnedColumns.includes(h)) header += PIN_BUTTON;

    let width = Math.max(box(content), box(header));
    if (mode === "narrow") width = Math.min(width, box(cap));
    widths[h] = Math.max(MIN_WIDTH, width);
  }
  return widths;
}

/** Text-width function for a CSS font string, backed by one canvas. */
export function textMeasurer(font) {
  const ctx = document.createElement("canvas").getContext("2d");
  ctx.font = font;
  return (text) => ctx.measureText(text).width;
}
