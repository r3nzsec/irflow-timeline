// Toolbar menus close on a click anywhere outside them.
//
// The menu bar has backdrop-filter, which makes it the containing block for position:fixed
// descendants. The click-catching overlay used to live inside it, so it covered only the bar
// and a click on the grid left the menu open. It must be portalled to <body>, and sit under
// the bar so the open dropdown stays clickable.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const source = fs.readFileSync(path.join(__dirname, "..", "src", "components", "MenuBar.jsx"), "utf8");

test("the menu dismiss overlay is rendered into <body>, under the menu bar", () => {
  assert.match(source, /const backdrop = \(closeFn\) => <MenuDismissLayer onClose=\{closeFn\} \/>;/);
  const layer = source.slice(source.indexOf("function MenuDismissLayer"), source.indexOf("export default function MenuBar"));
  assert.match(layer, /createPortal\([\s\S]*document\.body,?\s*\)/);
  const layerZ = Number(layer.match(/position: "fixed", inset: 0, zIndex: (\d+)/)[1]);
  const barZ = Number(source.match(/className="tle-menubar-shell"[^\n]*?zIndex: (\d+)/)[1]);
  assert.ok(layerZ < barZ, `overlay z-index ${layerZ} must be below the menu bar's ${barZ}`);
  assert.match(layer, /document\.addEventListener\("mousedown", onMouseDown, true\)/, "clicks on the bar itself close the menu too");
});

test("every toolbar menu uses it", () => {
  for (const setter of ["setFileMenuOpen", "setViewMenuOpen", "setActionsMenuOpen", "setToolsOpen", "setHelpMenuOpen"]) {
    assert.match(source, new RegExp(`\\{backdrop\\(\\(\\) => ${setter}\\(false\\)\\)\\}`), setter);
  }
});
