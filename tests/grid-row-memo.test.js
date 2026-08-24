// The grid renders ~80 rows and re-renders on every scroll frame. GridRow is memoized so
// a frame only re-renders the rows entering and leaving the viewport — but a memo is only
// as good as the stability of what is handed to it, and every one of those guarantees is
// easy to break with an edit that looks harmless.
//
// These are source contracts, in the style of p1-ui-contract.test.js: they lock the shape
// that makes the memo hold, so the cheap mistakes (an inline arrow in the context object,
// a callback that loses its useCallback) fail here instead of silently costing frames.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
const gridRow = read("src/components/GridRow.jsx");
const virtualGrid = read("src/components/VirtualGrid.jsx");
const app = read("src/App.jsx");

/** Body of the object literal passed to the rowCtx useMemo — the `({ … })` contents only. */
function rowCtxLiteral() {
  const marker = "const rowCtx = useMemo(() => ({";
  const start = virtualGrid.indexOf(marker);
  assert.notEqual(start, -1, "rowCtx useMemo not found in VirtualGrid.jsx");
  const end = virtualGrid.indexOf("}), [", start);
  assert.notEqual(end, -1, "rowCtx useMemo has no dependency array");
  return virtualGrid.slice(start + marker.length, end);
}

test("GridRow is memoized", () => {
  assert.match(gridRow, /import \{ memo \} from "react"/);
  assert.match(gridRow, /memo\(GridRowInner\)/);
  assert.match(gridRow, /export default GridRow/);
});

test("the row context is memoized and carries nothing freshly allocated", () => {
  const literal = rowCtxLiteral();
  // An arrow function or an inline object/array literal here gets a new identity on every
  // render, which makes the useMemo pointless and every row re-render every frame.
  assert.ok(!literal.includes("=>"), `rowCtx contains an inline function:\n${literal}`);
  assert.doesNotMatch(literal, /:\s*[[{]/, `rowCtx contains an inline object/array literal:\n${literal}`);
  // Shorthand-only, so each entry is traceable to a memoized source.
  assert.doesNotMatch(literal, /^\s*\w+:\s/m, `rowCtx should use shorthand properties only:\n${literal}`);
});

test("everything rowCtx carries is also declared in its dependency array", () => {
  const literal = rowCtxLiteral();
  const keys = literal
    .split(",")
    .map((s) => s.trim())
    .filter((s) => /^\w+$/.test(s));
  assert.ok(keys.length > 15, `expected the full row context, parsed ${keys.length} keys`);

  const depsStart = virtualGrid.indexOf("}), [", virtualGrid.indexOf("const rowCtx = useMemo"));
  const deps = virtualGrid.slice(depsStart, virtualGrid.indexOf("]);", depsStart));
  for (const key of keys) {
    assert.ok(
      new RegExp(`\\b${key}\\b`).test(deps),
      `rowCtx carries "${key}" but does not list it as a dependency — the row would render stale data`,
    );
  }
});

test("the functions rowCtx hands to every row are useCallback-stable in App.jsx", () => {
  for (const fn of ["gw", "fmtCell", "renderCell", "getRowBg", "handleRowClick", "handleBookmark", "handleCheckboxToggle"]) {
    assert.match(
      app,
      new RegExp(`const ${fn} = useCallback\\(`),
      `${fn} is passed into rowCtx, so it must be useCallback-wrapped or the memo misses every frame`,
    );
  }
});

test("row interaction handlers read volatile state through a ref, not through deps", () => {
  // lastClickedRow / allRowsSelected / currentFilterOptions all change when a row is
  // clicked. As useCallback deps they would give rowCtx a new identity on every click and
  // re-render all ~80 rows — defeating the per-row memo exactly when selection changes.
  assert.match(app, /rowActionsRef\.current = \{/);
  for (const dep of ["lastClickedRow", "allRowsSelected", "currentFilterOptions"]) {
    assert.ok(
      new RegExp(`rowActionsRef\\.current = \\{[^}]*\\b${dep}\\b`).test(app),
      `${dep} should be mirrored on rowActionsRef so the row handlers stay []-stable`,
    );
  }
  const clickDeps = app.slice(app.indexOf("const handleRowClick = useCallback("));
  const depArray = clickDeps.slice(clickDeps.indexOf("}, ["), clickDeps.indexOf("]);"));
  for (const dep of ["lastClickedRow", "allRowsSelected", "currentFilterOptions", "getRowIdAt"]) {
    assert.ok(!depArray.includes(dep), `handleRowClick must not take "${dep}" as a dependency`);
  }
});

test("per-row state that changes arrives as primitives, not recomputed inside the row", () => {
  // sel/bm/tabIndex are computed by the parent and compared by the memo. Deriving them
  // inside GridRow from selectedRows/allRowsSelected would require those in the context,
  // and both change identity on every selection change.
  assert.match(virtualGrid, /<GridRow[\s\S]{0,400}sel=\{isRowSelected\(/);
  assert.match(virtualGrid, /<GridRow[\s\S]{0,400}bm=\{!!ct\.bookmarkedSet\?\.has\(/);
  assert.match(virtualGrid, /<GridRow[\s\S]{0,400}tabIndex=\{/);
  for (const volatile of ["selectedRows", "allRowsSelected", "selectedRow"]) {
    assert.ok(
      !new RegExp(`\\b${volatile}\\b`).test(gridRow),
      `GridRow reads "${volatile}" directly; it should receive the resolved per-row value instead`,
    );
  }
});

test("GridRow reuses one empty-tags array instead of allocating per row", () => {
  // `ct.rowTags[id] || []` allocates a fresh array for every untagged row, 80× per frame.
  assert.match(gridRow, /const EMPTY_TAGS = \[\]/);
  assert.ok(
    !/\|\|\s*\[\]/.test(gridRow),
    "GridRow should fall back to EMPTY_TAGS rather than a fresh [] literal",
  );
});

test("the extracted row still renders the full cell set", () => {
  // Guards against the extraction having dropped a column lane.
  for (const marker of [
    "Bookmark - always sticky",
    "Checkbox cell",
    "Tags cell",
    "VT verdict cell",
    "Evidence pills cell",
    "Pinned data cells",
    "Scrollable data cells",
  ]) {
    assert.ok(gridRow.includes(marker), `GridRow lost the "${marker}" lane`);
  }
  assert.match(gridRow, /pinnedH\.map\(/);
  assert.match(gridRow, /windowedScrollH\.map\(/);
});
