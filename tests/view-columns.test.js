// View → Freeze / Unfreeze First Column, Hide Column on any
// header (right-click opens the header menu), and a hideable Tags column.
//
// These are wiring checks on the source; the behavior was checked by driving the app (see the PR).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const read = (...p) => fs.readFileSync(path.join(__dirname, "..", ...p), "utf8");

test("both View menus offer Freeze First Column and Unfreeze First Column", () => {
  const menu = read("electron", "menu.js");
  assert.match(menu, /label: "Freeze First Column",\s*click: \(\) => mainWindow\?\.webContents\.send\("trigger-first-column", "freeze"\)/);
  assert.match(menu, /label: "Unfreeze First Column",\s*click: \(\) => mainWindow\?\.webContents\.send\("trigger-first-column", "unfreeze"\)/);
  const bar = read("src", "components", "MenuBar.jsx");
  assert.match(bar, /label: "Freeze First Column",[^\n]*disabled: !ct\?\.dataReady \|\| firstColumnFrozen/);
  assert.match(bar, /label: "Unfreeze First Column",[^\n]*disabled: !ct\?\.dataReady \|\| !firstColumnFrozen/);
  assert.match(read("src", "App.jsx"), /listen\(tle\.onTriggerFirstColumn,/);
});

test("right-clicking any header, Tags included, opens the column menu", () => {
  const grid = read("src", "components", "VirtualGrid.jsx");
  assert.match(grid, /onContextMenu=\{\(e\) => openHeaderMenu\(e, "__tags__"\)\}/);
  assert.equal((grid.match(/onContextMenu=\{\(e\) => openHeaderMenu\(e, h\)\}/g) || []).length, 2, "pinned and scrollable headers");
});

test("the header menu's Hide Column is not limited to data columns", () => {
  const app = read("src", "App.jsx");
  const pinBlock = app.indexOf('...(contextMenu.colName !== "__tags__" ? [');
  const pinBlockEnd = app.indexOf("] : []),", pinBlock);
  const hide = app.indexOf('{ label: "Hide Column",', pinBlock);
  assert.ok(pinBlock > 0 && hide > pinBlockEnd, "Hide Column must come after the data-column-only Pin entry");
});

test("the Tags column can be hidden and shown from the Column Manager", () => {
  const modals = read("src", "components", "InlineModals.jsx");
  assert.match(modals, /aria-label="Show the Tags column"/);
  assert.match(modals, /new Set\(\[\.\.\.ct\.headers, "__tags__"\]\)/, "Hide All hides Tags too");
  const app = read("src", "App.jsx");
  assert.match(app, /const tagsHidden = !!ct\?\.hiddenColumns\?\.has\("__tags__"\);/);
  assert.match(app, /tagColWidth=\{visibleTagColWidth\} tagsHidden=\{tagsHidden\}/);
  assert.match(read("src", "components", "GridRow.jsx"), /\{!tagsHidden && \(/);
});
