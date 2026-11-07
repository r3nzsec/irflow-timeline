// The cell popup's copy controls show that they copied.
//
// Double-clicking a cell opens a popup whose Copy button used to give no sign of a copy (the
// status bar's "Copied" is behind the popup's overlay). Behavior was checked by driving the app;
// these keep the wiring in place.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const app = fs.readFileSync(path.join(__dirname, "..", "src", "App.jsx"), "utf8");

test("the popup's Copy buttons and converter values go through copyFromPopup", () => {
  assert.match(app, /\{copyButton\("value", cpCopyText\)\}/);
  assert.match(app, /\{copyButton\("decoded", cpDecoded, true\)\}/);
  assert.match(app, /onClick=\{\(\) => copyFromPopup\(`ts:\$\{label\}`, val\)\}/);
  assert.doesNotMatch(app, /navigator\.clipboard\?\.writeText\(cpDecoded\)/, "no silent copy left in the popup");
});

test("a copy is reported only after the clipboard accepts it", () => {
  const fn = app.slice(app.indexOf("const copyFromPopup = useCallback("), app.indexOf("const copyCell = useCallback("));
  assert.match(fn, /try \{ await navigator\.clipboard\.writeText\(text\); \} catch \{ ok = false; \}/);
  assert.match(fn, /setPopupCopied\(\{ key, ok, tick: Date\.now\(\) \}\)/);
});

test("the button says Copied or Copy failed and replays its press animation on every copy", () => {
  const btn = app.slice(app.indexOf("const copyButton = ("), app.indexOf("const cpCopyText ="));
  assert.match(btn, /key=\{done \? `\$\{key\}-\$\{done\.tick\}` : key\}/);
  assert.match(btn, /done\.ok \? "Copied" : "Copy failed"/);
  assert.match(btn, /animation: done \? "tle-copy-pop/);
  assert.match(app, /@keyframes tle-copy-pop \{/);
});

test("a successful copy fills the button with the theme's text color for one second", () => {
  const btn = app.slice(app.indexOf("const copyButton = ("), app.indexOf("const cpCopyText ="));
  assert.match(btn, /const fill = done \? \(done\.ok \? th\.text : th\.danger\) : null;/);
  assert.match(btn, /const ink = done \? \(done\.ok \? th\.modalBg : "#ffffff"\) : th\.text;/);
  assert.match(btn, /background: fill \|\| th\.btnBg/);
  const fn = app.slice(app.indexOf("const copyFromPopup = useCallback("), app.indexOf("const copyCell = useCallback("));
  assert.match(fn, /setTimeout\(\(\) => setPopupCopied\(null\), 1000\)/);
});
