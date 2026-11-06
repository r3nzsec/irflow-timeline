// Enter in Edit Filter applies the filter once.
//
// Enter in the value box applied the filter and closed the dialog, and the focus trap at once
// returned focus to the status bar's Edit Filter button, so the same Enter pressed that button
// and the dialog opened again. Checked in the app over CDP; these keep the two fixes in place.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const read = (p) => fs.readFileSync(path.join(__dirname, "..", p), "utf8");

test("Enter in the value box stops the key before applying", () => {
  const modal = read("src/components/modals/EditFilterModal.jsx");
  assert.match(modal, /onKeyDown=\{\(e\) => \{ if \(e\.key === "Enter"\) \{ e\.preventDefault\(\); handleApply\(\); \} \}\}/);
});

test("a closing modal returns focus only after the closing event, and only if focus was lost", () => {
  const trap = read("src/hooks/useFocusTrap.js");
  const cleanup = trap.slice(trap.indexOf("return () => {"), trap.indexOf("}, [active]);"));
  assert.match(cleanup, /setTimeout\(\(\) => \{/);
  assert.match(cleanup, /const focusLost = !now \|\| now === document\.body \|\| now === document\.documentElement;/);
  assert.match(cleanup, /if \(focusLost && prev instanceof HTMLElement && document\.contains\(prev\)\) prev\.focus\(\);/);
  assert.doesNotMatch(cleanup.replace(/setTimeout\([\s\S]*?\}, 0\);/, ""), /prev\.focus\(\)/, "no immediate restore");
});
