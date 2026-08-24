// Row-window logic behind the virtual grid: which slice of the loaded window the viewport
// renders, and when a scroll position genuinely needs a new window from SQL.
//
// Both were sources of visible flicker. The slice was anchored to `si` rather than to the
// row the slice actually starts at, and the fetch planner asked for a window shift that
// could not happen at the head or tail of the result set.
const test = require("node:test");
const assert = require("node:assert");

// grid-layout.js is renderer ESM; the suite runs as CJS, so load it once per file.
const gridLayout = import("../src/utils/grid-layout.js");

const VIRTUAL_WINDOW = 10000;
const AHEAD = 2000;

test("getWindowSlice: window starting at or before si renders from si", async () => {
  const { getWindowSlice } = await gridLayout;
  // The ordinary case — the fetch centres the window well below the viewport.
  const slice = getWindowSlice({ si: 8000, ei: 8080, rowOffset: 5000, rowCount: 10000 });
  assert.deepEqual(slice, { start: 3000, end: 3080, visibleStart: 8000 });
});

test("getWindowSlice: window starting after si anchors to the window, not to si", async () => {
  const { getWindowSlice } = await gridLayout;
  // Scrolling up into the rows just above the loaded window. rows[0] is absolute row 5000,
  // so the slice must render from 5000. Anchoring it to si=4950 shifted every row up by 50
  // and painted them over the skeletons covering 4950..5000.
  const slice = getWindowSlice({ si: 4950, ei: 5040, rowOffset: 5000, rowCount: 10000 });
  assert.equal(slice.start, 0);
  assert.equal(slice.end, 40, "only the 40 rows the window actually holds");
  assert.equal(slice.visibleStart, 5000, "first sliced row is absolute row 5000");
});

test("getWindowSlice: viewport entirely outside the window yields an empty slice", async () => {
  const { getWindowSlice } = await gridLayout;
  const below = getWindowSlice({ si: 100, ei: 180, rowOffset: 5000, rowCount: 10000 });
  assert.equal(below.end - below.start, 0);
  const above = getWindowSlice({ si: 90000, ei: 90080, rowOffset: 5000, rowCount: 10000 });
  assert.equal(above.end - above.start, 0);
});

test("getWindowSlice: slice never runs past the rows actually loaded", async () => {
  const { getWindowSlice } = await gridLayout;
  // Tail of the window: ei reaches beyond the loaded rows, so the slice stops short and
  // the uncovered indices are left to the skeleton pass.
  const slice = getWindowSlice({ si: 9950, ei: 10040, rowOffset: 0, rowCount: 10000 });
  assert.deepEqual(slice, { start: 9950, end: 10000, visibleStart: 9950 });
});

test("getWindowSlice: empty window is handled without a negative-length slice", async () => {
  const { getWindowSlice } = await gridLayout;
  const slice = getWindowSlice({ si: 500, ei: 580, rowOffset: 0, rowCount: 0 });
  assert.deepEqual(slice, { start: 0, end: 0, visibleStart: 0 });
});

test("rowWindowCovers: exact and off-by-one boundaries", async () => {
  const { planWindowFetch, rowWindowCovers } = await gridLayout;
  assert.equal(rowWindowCovers(1000, 500, 1000, 500), true, "flush fit covers");
  assert.equal(rowWindowCovers(1000, 500, 1000, 501), false, "one row past the end");
  assert.equal(rowWindowCovers(1000, 500, 999, 10), false, "one row before the start");
});

const plan = async (over) => (await gridLayout).planWindowFetch({
  visibleRows: 80,
  fetchLimit: VIRTUAL_WINDOW,
  ahead: AHEAD,
  ...over,
});

test("planWindowFetch: mid-window scrolling asks for nothing", async () => {
  const { needsFetch } = await plan({ scrollRow: 5000, rowOffset: 0, loadedRows: 10000, totalFiltered: 140000 });
  assert.equal(needsFetch, false);
});

test("planWindowFetch: no refetch at the head of a large result set", async () => {
  // rowOffset is already 0 and cannot go lower, but scrollRow < rowOffset + ahead, so the
  // prefetch margin fires on every scroll frame in the first 2000 rows. Each fetch used to
  // re-issue the identical 10k-row query and swap `rows` for an identical array.
  for (const scrollRow of [0, 200, 900, 1999]) {
    const { needsFetch, nextOffset } = await plan({ scrollRow, rowOffset: 0, loadedRows: 10000, totalFiltered: 140000 });
    assert.equal(nextOffset, 0, `offset cannot move below 0 at row ${scrollRow}`);
    assert.equal(needsFetch, false, `no refetch at row ${scrollRow}`);
  }
});

test("planWindowFetch: no refetch at the tail of a large result set", async () => {
  // Symmetric case: the window is pinned at totalFiltered - fetchLimit.
  const rowOffset = 130000;
  for (const scrollRow of [138000, 139500, 139900]) {
    const { needsFetch, nextOffset } = await plan({ scrollRow, rowOffset, loadedRows: 10000, totalFiltered: 140000 });
    assert.equal(nextOffset, rowOffset, `offset stays clamped at row ${scrollRow}`);
    assert.equal(needsFetch, false, `no refetch at row ${scrollRow}`);
  }
});

test("planWindowFetch: approaching the window edge mid-dataset does refetch", async () => {
  const { needsFetch, nextOffset } = await plan({ scrollRow: 8500, rowOffset: 0, loadedRows: 10000, totalFiltered: 140000 });
  assert.equal(needsFetch, true, "within `ahead` of the window end and the window can still move");
  assert.equal(nextOffset, 3500, "recentres the window on the scroll position");
});

test("planWindowFetch: a jump outside the window always refetches", async () => {
  const { needsFetch, nextOffset } = await plan({ scrollRow: 100000, rowOffset: 0, loadedRows: 10000, totalFiltered: 140000 });
  assert.equal(needsFetch, true);
  assert.equal(nextOffset, 95000);
});

test("planWindowFetch: a fully loaded result set never refetches", async () => {
  // Small tab — every row is already in the window, so no scroll position needs SQL.
  for (const scrollRow of [0, 200, 4999]) {
    assert.equal((await plan({ scrollRow, rowOffset: 0, loadedRows: 5000, totalFiltered: 5000 })).needsFetch, false);
  }
});

test("planWindowFetch: reopening a tab scrolled past its window refetches at that row", async () => {
  // Tab switch restores the scroll deep into the dataset while the tab still holds its old
  // window. The fetch must centre on the restored row, not reset the window to 0.
  const { needsFetch, nextOffset } = await plan({ scrollRow: 80000, rowOffset: 0, loadedRows: 10000, totalFiltered: 140000 });
  assert.equal(needsFetch, true);
  assert.equal(nextOffset, 75000);
});

test("planWindowFetch: the window it plans covers the viewport it planned for", async () => {
  const { rowWindowCovers } = await gridLayout;
  // Property check across the dataset: whatever offset the planner picks must leave the
  // viewport inside the window, otherwise the grid lands on skeletons again immediately.
  const total = 140000;
  for (let scrollRow = 0; scrollRow < total; scrollRow += 1237) {
    const { nextOffset } = await plan({ scrollRow, rowOffset: 0, loadedRows: 10000, totalFiltered: total });
    const loaded = Math.min(VIRTUAL_WINDOW, total - nextOffset);
    assert.ok(
      rowWindowCovers(nextOffset, loaded, scrollRow, Math.min(80, total - scrollRow)),
      `planned window ${nextOffset}..${nextOffset + loaded} misses viewport at row ${scrollRow}`,
    );
  }
});
