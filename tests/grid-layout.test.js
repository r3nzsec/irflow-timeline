const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("grid content width includes resized structural columns", async () => {
  const { getGridContentWidth } = await import("../src/utils/grid-layout.js");
  const width = getGridContentWidth({
    visibleColumns: ["Category", "Message"],
    columnWidths: {
      Category: 120,
      Message: 480,
    },
    leadingWidth: 58,
    tagWidth: 100,
    vtWidth: 80,
    evidenceWidth: 360,
  });

  assert.equal(width, 1198);
});

test("grid content width omits inactive optional columns", async () => {
  const { getGridContentWidth } = await import("../src/utils/grid-layout.js");
  const width = getGridContentWidth({
    visibleColumns: ["Category", "Message"],
    columnWidths: { Category: 120 },
    leadingWidth: 58,
    tagWidth: 100,
  });

  assert.equal(width, 428);
});

test("keyboard row navigation reserves the sticky header and filter area", async () => {
  const { getRowScrollTarget } = await import("../src/utils/grid-layout.js");
  const target = getRowScrollTarget({
    rowIndex: 20,
    rowHeight: 26,
    logicalScrollTop: 0,
    viewportHeight: 400,
    stickyHeight: 62,
  });

  // Usable body height is 338px, so row 20's bottom (546px) requires 208px
  // of logical scrolling. Treating the full viewport as data would stop at 146.
  assert.equal(target, 208);
});

test("keyboard row navigation leaves a fully visible row in place", async () => {
  const { getRowScrollTarget } = await import("../src/utils/grid-layout.js");
  const target = getRowScrollTarget({
    rowIndex: 10,
    rowHeight: 26,
    logicalScrollTop: 100,
    viewportHeight: 400,
    stickyHeight: 62,
  });

  assert.equal(target, null);
});

test("visible row range reports viewport rows without overscan", async () => {
  const { getVisibleRowRange } = await import("../src/utils/grid-layout.js");

  assert.deepEqual(
    getVisibleRowRange({
      totalCount: 2_430_118,
      logicalScrollTop: 20_000 * 26,
      viewportHeight: 50 * 26,
      rowHeight: 26,
    }),
    { start: 20_001, end: 20_050 },
  );
  assert.deepEqual(
    getVisibleRowRange({
      totalCount: 0,
      logicalScrollTop: 0,
      viewportHeight: 500,
      rowHeight: 26,
    }),
    { start: 0, end: 0 },
  );
});

test("sticky grid surfaces are opaque and structural cells use border-box sizing", () => {
  // The grid's markup lives in two files: VirtualGrid.jsx owns the header, filter row and
  // group rows; the data row was extracted into the memoized GridRow.jsx. This contract is
  // about the rendered grid, so it reads both.
  const source = ["VirtualGrid.jsx", "GridRow.jsx"]
    .map((f) => fs.readFileSync(path.join(__dirname, "..", "src", "components", f), "utf8"))
    .join("\n");

  assert.match(source, /const stickyHeaderBg = th\.headerBg;/);
  assert.match(source, /const stickyFilterBg = th\.bg;/);
  assert.doesNotMatch(source, /background: th\.headerBg \+ "cc"/);
  assert.doesNotMatch(source, /background: th\.bg \+ "cc"/);
  assert.match(
    source,
    /width: tagColWidth, minWidth: tagColWidth, boxSizing: "border-box", padding: "0 4px"/,
  );
  assert.match(
    source,
    /width: evW, minWidth: EVIDENCE_COL_MIN_WIDTH, boxSizing: "border-box", padding: "0 6px"/,
  );
});
