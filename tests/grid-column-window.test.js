// Horizontal virtualization geometry.
//
// Rows are windowed vertically but every visible column used to render for every visible
// row — 40-80 columns × ~80 rows on a Plaso or EVTX tab. These helpers pick the slice of
// scrollable columns that is actually on screen and the spacer widths that stand in for
// the rest, so the row keeps its full width and the horizontal scrollbar keeps its extent.
//
// The invariant that matters: whatever the window reports, padLeft + rendered widths +
// padRight must always equal the strip's total width. If that ever drifts, columns and
// their headers visibly desync.

const test = require("node:test");
const assert = require("node:assert/strict");

const gridLayout = import("../src/utils/grid-layout.js");

// A realistic wide tab: 60 columns, mixed widths.
const COLUMNS = Array.from({ length: 60 }, (_, i) => `Col${i}`);
const WIDTHS = Object.fromEntries(COLUMNS.map((c, i) => [c, 100 + (i % 5) * 60]));

async function geom() {
  const { getColumnGeometry } = await gridLayout;
  return getColumnGeometry(COLUMNS, WIDTHS);
}

test("getColumnGeometry: offsets are the running sum of column widths", async () => {
  const { getColumnGeometry } = await gridLayout;
  const g = getColumnGeometry(["a", "b", "c"], { a: 100, b: 250, c: 40 });
  assert.deepEqual(g.offsets, [0, 100, 350]);
  assert.equal(g.totalWidth, 390);
});

test("getColumnGeometry: unknown widths fall back to the grid default", async () => {
  const { getColumnGeometry } = await gridLayout;
  const g = getColumnGeometry(["a", "b"], {}, 150);
  assert.deepEqual(g.offsets, [0, 150]);
  assert.equal(g.totalWidth, 300);
});

test("getColumnGeometry: no columns is not an error", async () => {
  const { getColumnGeometry } = await gridLayout;
  assert.deepEqual(getColumnGeometry([], {}), { offsets: [], totalWidth: 0 });
});

test("an unmeasured viewport renders every column rather than guessing", async () => {
  const { getColumnWindow } = await gridLayout;
  const g = await geom();
  // First paint, or a tab never shown: clientWidth is 0. Blanking the grid would be far
  // worse than rendering it all, so the window opens fully.
  const w = getColumnWindow({ ...g, scrollLeft: 0, viewportWidth: 0 });
  assert.deepEqual(w, { start: 0, end: 60, padLeft: 0, padRight: 0 });
});

test("at scrollLeft 0 the window starts at the first column with no left spacer", async () => {
  const { getColumnWindow } = await gridLayout;
  const g = await geom();
  const w = getColumnWindow({ ...g, scrollLeft: 0, viewportWidth: 1600, frozenWidth: 300 });
  assert.equal(w.start, 0);
  assert.equal(w.padLeft, 0);
  assert.ok(w.end < 60, `expected a partial window on a 60-column tab, got ${w.end}`);
});

test("the window covers the visible band, and overscan extends it on both sides", async () => {
  const { getColumnWindow } = await gridLayout;
  const g = await geom();
  const scrollLeft = 2400, viewportWidth = 1600, frozenWidth = 300;
  const bare = getColumnWindow({ ...g, scrollLeft, viewportWidth, frozenWidth, overscan: 0 });
  const over = getColumnWindow({ ...g, scrollLeft, viewportWidth, frozenWidth, overscan: 3 });

  // Every column the viewport can see is inside the un-overscanned window.
  const from = scrollLeft;
  const to = scrollLeft + viewportWidth - frozenWidth;
  for (let i = 0; i < 60; i++) {
    const left = g.offsets[i];
    const right = left + (WIDTHS[COLUMNS[i]]);
    if (right > from && left < to) {
      assert.ok(i >= bare.start && i < bare.end, `column ${i} is on screen but outside the window`);
    }
  }
  assert.equal(over.start, Math.max(0, bare.start - 3));
  assert.equal(over.end, Math.min(60, bare.end + 3));
});

test("spacers plus rendered columns always reconstruct the full strip width", async () => {
  const { getColumnWindow } = await gridLayout;
  const g = await geom();
  // This is the one that keeps headers aligned with their cells. Sweep the whole strip.
  for (let scrollLeft = 0; scrollLeft <= g.totalWidth; scrollLeft += 137) {
    for (const viewportWidth of [640, 1600, 3200]) {
      const w = getColumnWindow({ ...g, scrollLeft, viewportWidth, frozenWidth: 300 });
      let rendered = 0;
      for (let i = w.start; i < w.end; i++) rendered += WIDTHS[COLUMNS[i]];
      assert.equal(
        w.padLeft + rendered + w.padRight,
        g.totalWidth,
        `width drift at scrollLeft=${scrollLeft} viewport=${viewportWidth}`,
      );
    }
  }
});

test("scrolled to the far right the window reaches the last column and drops the right spacer", async () => {
  const { getColumnWindow } = await gridLayout;
  const g = await geom();
  const w = getColumnWindow({ ...g, scrollLeft: g.totalWidth, viewportWidth: 1600, frozenWidth: 300 });
  assert.equal(w.end, 60);
  assert.equal(w.padRight, 0);
});

test("a viewport wider than the content renders everything", async () => {
  const { getColumnWindow } = await gridLayout;
  const g = await geom();
  const w = getColumnWindow({ ...g, scrollLeft: 0, viewportWidth: g.totalWidth + 1000, frozenWidth: 0 });
  assert.deepEqual([w.start, w.end, w.padLeft, w.padRight], [0, 60, 0, 0]);
});

test("a frozen block wider than the viewport still renders a column", async () => {
  const { getColumnWindow } = await gridLayout;
  const g = await geom();
  // Pin enough columns and the scrollable strip has no room left. The row must not come
  // out structurally empty.
  const w = getColumnWindow({ ...g, scrollLeft: 600, viewportWidth: 400, frozenWidth: 900, overscan: 0 });
  assert.ok(w.end > w.start, "window collapsed to nothing");
  assert.equal(w.padLeft + (g.offsets[w.end] ?? g.totalWidth) - g.offsets[w.start] + w.padRight, g.totalWidth);
});

test("a single-column tab is handled without spacers", async () => {
  const { getColumnGeometry, getColumnWindow } = await gridLayout;
  const g = getColumnGeometry(["only"], { only: 220 });
  const w = getColumnWindow({ ...g, scrollLeft: 0, viewportWidth: 1200, frozenWidth: 300 });
  assert.deepEqual(w, { start: 0, end: 1, padLeft: 0, padRight: 0 });
});

test("no scrollable columns yields an empty window, not a spacer-only row", async () => {
  const { getColumnWindow } = await gridLayout;
  const w = getColumnWindow({ offsets: [], totalWidth: 0, scrollLeft: 0, viewportWidth: 1200 });
  assert.deepEqual(w, { start: 0, end: 0, padLeft: 0, padRight: 0 });
});

// ── Wiring contracts ────────────────────────────────────────────────────────────────
// Header, filter row and data row must render the same column slice. If one of them ever
// goes back to mapping the full `scrollH`, the grid still looks right at scrollLeft 0 and
// silently desyncs the moment you scroll sideways — so lock it here.

const fs = require("node:fs");
const path = require("node:path");
const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");

test("all three grid lanes render the windowed slice, not the full column list", () => {
  const virtualGrid = read("src/components/VirtualGrid.jsx");
  const gridRow = read("src/components/GridRow.jsx");

  // Header and filter row.
  assert.equal(
    (virtualGrid.match(/windowedScrollH\.map\(/g) || []).length, 2,
    "expected the header and filter rows to map the windowed slice",
  );
  assert.ok(
    !/[^d]scrollH\.map\(/.test(virtualGrid),
    "a lane in VirtualGrid still maps the full scrollH and will desync on horizontal scroll",
  );
  // Data row.
  assert.match(gridRow, /windowedScrollH\.map\(/);
  assert.ok(!/[^d]scrollH\.map\(/.test(gridRow), "GridRow still maps the full scrollH");
});

test("every windowed lane is bracketed by both spacers", () => {
  const sources = {
    "VirtualGrid.jsx": read("src/components/VirtualGrid.jsx"),
    "GridRow.jsx": read("src/components/GridRow.jsx"),
  };
  // Two lanes in VirtualGrid, one in GridRow — each needs a left and a right spacer, or the
  // row loses width and the header stops lining up with its cells.
  assert.equal((sources["VirtualGrid.jsx"].match(/colWindow\.padLeft > 0 &&/g) || []).length, 2);
  assert.equal((sources["VirtualGrid.jsx"].match(/colWindow\.padRight > 0 &&/g) || []).length, 2);
  assert.equal((sources["GridRow.jsx"].match(/colWindow\.padLeft > 0 &&/g) || []).length, 1);
  assert.equal((sources["GridRow.jsx"].match(/colWindow\.padRight > 0 &&/g) || []).length, 1);
  for (const [name, src] of Object.entries(sources)) {
    // Spacers must not shrink, or flex would eat the padding they exist to provide.
    const spacers = src.match(/aria-hidden="true" style=\{\{ width: colWindow\.pad\w+[^}]*\}\}/g) || [];
    assert.ok(spacers.length > 0, `${name} has no spacers`);
    for (const spacer of spacers) {
      assert.match(spacer, /flexShrink: 0/, `${name}: spacer can shrink — ${spacer}`);
      assert.match(spacer, /minWidth: colWindow\.pad/, `${name}: spacer has no minWidth — ${spacer}`);
    }
  }
});

test("the windowed slice is memoized so it cannot break GridRow's memo", () => {
  const virtualGrid = read("src/components/VirtualGrid.jsx");
  // windowedScrollH rides in rowCtx. A bare .slice() per render would hand the context a
  // new identity 60x/second and undo the row memo entirely.
  assert.match(
    virtualGrid,
    /const windowedScrollH = useMemo\(\s*\(\) => scrollH\.slice\(colWindow\.start, colWindow\.end\),\s*\[scrollH, colWindow\.start, colWindow\.end\],?\s*\)/,
    "windowedScrollH must be useMemo'd on the window bounds",
  );
});

test("horizontal scroll reaches state, and only when the window actually moves", () => {
  const app = read("src/App.jsx");
  assert.match(app, /scrollLeftRef\.current = e\.target\.scrollLeft/, "scrollLeft is never read from the event");
  assert.match(app, /setScrollLeft\(nextLeft\)/, "scrollLeft never reaches state");
  // Per-pixel updates would re-render the tree for horizontal movement that changes nothing.
  assert.match(app, /const colUnchanged = nextCol\.start === cw\.start && nextCol\.end === cw\.end/);
  assert.match(app, /if \(rowUnchanged && colUnchanged\) return;/);
});

test("virtualized cells carry explicit ARIA column indices", () => {
  const virtualGrid = read("src/components/VirtualGrid.jsx");
  const gridRow = read("src/components/GridRow.jsx");
  // Omitting cells from the DOM makes implicit positional indices wrong, so every cell in
  // the row states its own — including the always-rendered sticky lanes.
  assert.match(gridRow, /aria-colindex=\{1\}/);
  assert.match(gridRow, /aria-colindex=\{2\}/);
  assert.match(gridRow, /aria-colindex=\{3\}/);
  assert.match(gridRow, /aria-colindex=\{colIdxVt\}/);
  assert.match(gridRow, /aria-colindex=\{colIdxEvidence\}/);
  assert.match(gridRow, /aria-colindex=\{firstPinnedColIndex \+ pi\}/);
  assert.match(gridRow, /aria-colindex=\{firstScrollColIndex \+ wi\}/);
  // The header's leading cell covers bookmark + checkbox in one box.
  assert.match(virtualGrid, /aria-colindex=\{1\} aria-colspan=\{2\}/);
  assert.match(virtualGrid, /aria-colindex=\{firstScrollColIndex \+ wi\}/);
  // aria-colcount stays the full column count — it describes the table, not the window.
  assert.match(virtualGrid, /aria-colcount=\{_structuralColCount \+ pinnedH\.length \+ scrollH\.length\}/);
});

test("the scroll container's width is measured, not inferred from the window", () => {
  const app = read("src/App.jsx");
  // Deriving it from window.innerWidth would silently over-render whenever the grid is
  // not full-bleed; reading clientWidth during render would be a frame stale on mount.
  assert.match(app, /new ResizeObserver\([\s\S]{0,240}setGridViewportW/);
  assert.match(app, /viewportWidth: gridViewportW/);
  assert.match(app, /frozenWidth = pinnedOffsets\.totalWidth/);
});
