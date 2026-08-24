/**
 * Renderer-only grid geometry helpers.
 *
 * Keep these calculations outside React so column-width and keyboard-scroll
 * regressions can be covered by the Node test suite.
 */

export function getGridContentWidth({
  visibleColumns = [],
  columnWidths = {},
  defaultColumnWidth = 150,
  leadingWidth = 0,
  tagWidth = 0,
  vtWidth = 0,
  evidenceWidth = 0,
} = {}) {
  const dataWidth = visibleColumns.reduce(
    (sum, column) => sum + (columnWidths[column] || defaultColumnWidth),
    0,
  );
  return dataWidth + leadingWidth + tagWidth + vtWidth + evidenceWidth;
}

export function getGridBodyViewportHeight(
  viewportHeight,
  stickyHeight,
  minimumHeight = 1,
) {
  return Math.max(minimumHeight, viewportHeight - stickyHeight);
}

export function getVisibleRowRange({
  totalCount,
  logicalScrollTop,
  viewportHeight,
  rowHeight,
} = {}) {
  const count = Math.max(0, Number(totalCount) || 0);
  if (count === 0) return { start: 0, end: 0 };

  const height = Math.max(1, Number(rowHeight) || 1);
  const scrollTop = Math.max(0, Number(logicalScrollTop) || 0);
  const visibleHeight = Math.max(height, Number(viewportHeight) || height);
  const start = Math.min(count, Math.floor(scrollTop / height) + 1);
  const end = Math.min(count, Math.max(start, Math.ceil((scrollTop + visibleHeight) / height)));
  return { start, end };
}

export function getRowScrollTarget({
  rowIndex,
  rowHeight,
  logicalScrollTop,
  viewportHeight,
  stickyHeight,
} = {}) {
  const bodyHeight = getGridBodyViewportHeight(
    viewportHeight,
    stickyHeight,
    rowHeight,
  );
  const rowTop = rowIndex * rowHeight;
  const rowBottom = rowTop + rowHeight;

  if (rowTop < logicalScrollTop) return rowTop;
  if (rowBottom > logicalScrollTop + bodyHeight) {
    return Math.max(0, rowBottom - bodyHeight);
  }
  return null;
}

/** Does the loaded row window fully cover the rows the viewport is about to show? */
export function rowWindowCovers(rowOffset, rowCount, firstVisibleRow, visibleRowCount) {
  const start = rowOffset || 0;
  const end = start + (rowCount || 0);
  return firstVisibleRow >= start && firstVisibleRow + visibleRowCount <= end;
}

/**
 * Map the logical row range [si, ei) onto the loaded window [rowOffset, rowOffset+rowCount).
 *
 * `visibleStart` is the absolute index the returned slice actually begins at. It differs
 * from `si` whenever the loaded window starts *after* si — scrolling up into the rows just
 * above it — and rendering that slice from `si` shifts every row in it up by the
 * difference, painting real rows on top of the skeletons covering the same band.
 */
export function getWindowSlice({ si = 0, ei = 0, rowOffset = 0, rowCount = 0 } = {}) {
  const start = Math.max(0, Math.min(rowCount, si - rowOffset));
  const end = Math.max(start, Math.min(rowCount, ei - rowOffset));
  return { start, end, visibleStart: rowOffset + start };
}

/**
 * Decide whether a scroll position needs a new row window, and where that window starts.
 *
 * Mirrors the offset the fetch itself would choose so the caller can drop a fetch that
 * would land on the offset already loaded. Without that check the prefetch margins keep
 * asking for a shift while the window sits clamped at the head or tail of the result set,
 * and each no-op fetch still swaps `rows` for an identical array and re-renders the grid.
 */
export function planWindowFetch({
  scrollRow = 0,
  rowOffset = 0,
  loadedRows = 0,
  totalFiltered = 0,
  visibleRows = 0,
  fetchLimit = 0,
  ahead = 0,
} = {}) {
  const covers = rowWindowCovers(rowOffset, loadedRows, scrollRow, visibleRows);
  // Whole result set already loaded from row 0 — no window left to move to.
  if (rowOffset === 0 && loadedRows >= totalFiltered) return { needsFetch: false, nextOffset: rowOffset };
  const windowEnd = rowOffset + loadedRows;
  const wantsShift = !covers
    || scrollRow < rowOffset + ahead
    || scrollRow + visibleRows > windowEnd - ahead;
  if (!wantsShift) return { needsFetch: false, nextOffset: rowOffset };
  const maxOffset = totalFiltered > fetchLimit ? totalFiltered - fetchLimit : 0;
  const nextOffset = Math.max(0, Math.min(maxOffset, scrollRow - Math.floor(fetchLimit / 2)));
  if (nextOffset === rowOffset && covers) return { needsFetch: false, nextOffset };
  return { needsFetch: true, nextOffset };
}

/**
 * Prefix-sum x offsets for a column list, in the coordinate space of the scrollable
 * column strip (offsets[0] === 0, measured from the first scrollable column).
 */
export function getColumnGeometry(columns = [], columnWidths = {}, defaultWidth = 150) {
  const offsets = new Array(columns.length);
  let x = 0;
  for (let i = 0; i < columns.length; i++) {
    offsets[i] = x;
    x += columnWidths?.[columns[i]] || defaultWidth;
  }
  return { offsets, totalWidth: x };
}

/**
 * Which slice of the scrollable columns is worth rendering, plus the spacer widths that
 * stand in for the rest.
 *
 * Rows are `display: flex` with an explicit total width, so two zero-content spacers keep
 * both the layout and the horizontal scroll extent intact without any absolute
 * positioning — and the sticky columns, which render before the left spacer, are
 * untouched.
 *
 * The frozen block (bookmark, checkbox, tags, VT, evidence, pinned columns) is painted
 * over the leftmost `frozenWidth` px of the viewport, so in strip-relative coordinates the
 * band actually on screen is exactly [scrollLeft, scrollLeft + viewportWidth - frozenWidth).
 */
export function getColumnWindow({
  offsets = [],
  totalWidth = 0,
  scrollLeft = 0,
  viewportWidth = 0,
  frozenWidth = 0,
  overscan = 3,
} = {}) {
  const n = offsets.length;
  if (n === 0) return { start: 0, end: 0, padLeft: 0, padRight: 0 };
  // Viewport not measured yet (first paint, or a tab that has never been shown). Render
  // everything: a wrong guess would blank the grid, whereas a full render is merely slow.
  if (!(viewportWidth > 0)) return { start: 0, end: n, padLeft: 0, padRight: 0 };

  const from = Math.max(0, scrollLeft);
  const to = from + Math.max(0, viewportWidth - frozenWidth);

  let start = 0;
  while (start < n - 1 && offsets[start + 1] <= from) start++;
  let end = start;
  while (end < n && offsets[end] < to) end++;
  // A frozen block wider than the viewport leaves no room at all; still render one column
  // so the row is never structurally empty.
  if (end <= start) end = Math.min(n, start + 1);

  start = Math.max(0, start - overscan);
  end = Math.min(n, end + overscan);
  return {
    start,
    end,
    padLeft: offsets[start],
    padRight: end < n ? totalWidth - offsets[end] : 0,
  };
}
